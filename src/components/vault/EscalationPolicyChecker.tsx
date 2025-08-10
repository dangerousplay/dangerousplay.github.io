import {init, type Z3_ast} from 'z3-solver';
import {useEffect, useState} from "react";
import {Z3_lbool} from "z3-solver/build/low-level/types.__GENERATED__";

import * as hcl from "hcl2-parser"


const exampleCurrentPolicy = `path "secret/app/cookiebot/*" {
  capabilities = ["read"]
}
path "secret/app/cookiebot/admin" {
  capabilities = ["deny"]
}`

const exampleNewPolicy = `path "secret/app/cookiebot/*" {
  capabilities = ["read"]
}`

type PolicyCheckResult = {
  result: boolean,
  path: string | null,
  capability: string | null,
  z3: {
    currentPolicyAst: string,
    newPolicyAst: string
  }
}

async function initZ3Checker() {
  const { Z3 } = await init();

  /**
   * Compares two paths to determine their priority according to Vault's rules.
   * Returns a negative number if path1 has lower priority, positive if path1 has higher priority.
   *
   * Rules for P1 vs P2 (lower priority):
   * 1. First wildcard (+) or glob (*) occurs earlier in P1.
   * 2. P1 ends in * and P2 doesn't.
   * 3. P1 has more + segments.
   * 4. P1 is shorter.
   * 5. P1 is smaller lexicographically.
   */
  function comparePathPriority(path1: string, path2: string): number {

    // Rule 1: Longest matching prefix. A path with a wildcard appearing later is more specific.
    const firstWildcard1 = Math.min(path1.indexOf('+') > -1 ? path1.indexOf('+') : Infinity, path1.indexOf('*') > -1 ? path1.indexOf('*') : Infinity);
    const firstWildcard2 = Math.min(path2.indexOf('+') > -1 ? path2.indexOf('+') : Infinity, path2.indexOf('*') > -1 ? path2.indexOf('*') : Infinity);
    if (firstWildcard1 !== firstWildcard2) {
      // The path with the later wildcard has a longer literal prefix, so it's higher priority.
      return firstWildcard1 - firstWildcard2;
    }

    // Rule 2: Ending with *. A path that does NOT end with '*' has higher priority.
    const endsWithStar1 = path1.endsWith('*');
    const endsWithStar2 = path2.endsWith('*');
    if (endsWithStar1 !== endsWithStar2) {
      // If path1 ends with star and path2 does not, path1 has lower priority.
      return endsWithStar1 ? -1 : 1;
    }

    // Rule 3: Number of + wildcards (fewer is higher priority)
    const plusCount1 = (path1.match(/\+/g) || []).length;
    const plusCount2 = (path2.match(/\+/g) || []).length;
    if (plusCount1 !== plusCount2) {
      return plusCount2 - plusCount1;
    }

    // Rule 4: Path length (longer is higher priority)
    if (path1.length !== path2.length) {
      return path1.length - path2.length;
    }

    // Rule 5: Lexicographic comparison (a "smaller" path is higher priority)
    return path2.localeCompare(path1);
  }

  function buildRegexFromPath(ctx, path) {
    const reParts: Z3_ast[] = [];

    function wildcardRanges() {
      return [
        Z3.mk_re_range(ctx, Z3.mk_string(ctx, "a"), Z3.mk_string(ctx, "z")),
        Z3.mk_re_range(ctx, Z3.mk_string(ctx, "A"), Z3.mk_string(ctx, "Z")),
        Z3.mk_re_range(ctx, Z3.mk_string(ctx, "0"), Z3.mk_string(ctx, "9")),
        Z3.mk_seq_to_re(ctx, Z3.mk_string(ctx, "-")),
        Z3.mk_seq_to_re(ctx, Z3.mk_string(ctx, "_")),
        Z3.mk_seq_to_re(ctx, Z3.mk_string(ctx, "."))
      ];
    }

    // Split path by + or * at the end
    const parts = path.split(/([+]|\*$)/);

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];

      if (part === "*") {
        const ranges = wildcardRanges();
        ranges.push(Z3.mk_seq_to_re(ctx, Z3.mk_string(ctx, "/")));

        const unionRanges = Z3.mk_re_union(ctx, ranges);

        const wildcard = Z3.mk_re_star(ctx, unionRanges);
        reParts.push(wildcard);
      } else if (part === "+") {
        const ranges = wildcardRanges();
        const unionRanges = Z3.mk_re_union(ctx, ranges);

        const plus = Z3.mk_re_plus(ctx, unionRanges);
        reParts.push(plus);
      } else if (part) {
        reParts.push(Z3.mk_seq_to_re(ctx, Z3.mk_string(ctx, part)));
      }
    }

    if (reParts.length < 2) {
      return reParts[0];
    }

    return Z3.mk_re_concat(ctx, reParts)
  }

  function buildCapabilitiesMatch(ctx, inputCap, capabilities) {
      const capMatches = capabilities
          .filter(cap => cap !== 'deny')
          .map(cap => Z3.mk_eq(ctx, inputCap, Z3.mk_string(ctx, cap)));

      if (capMatches.length === 0) {
          // If only deny was present or no capabilities are listed, this policy cannot grant any capability.
          return Z3.mk_false(ctx);
      }
      return Z3.mk_or(ctx, capMatches);
  }

  function buildPolicyMatch(ctx, inputPath, inputCap, rules) {
   const allPaths = Object.keys(rules);

    // 1. Deny rule: if any matching policy has "deny", access is denied.
    const denyPaths = allPaths.filter(p => rules[p].includes('deny'));
    const denyMatchExprs = denyPaths.map(p => Z3.mk_seq_in_re(ctx, inputPath, buildRegexFromPath(ctx, p)));
    const isDenied = Z3.mk_or(ctx, denyMatchExprs);

    // 2. Allow rule: based on the highest-priority matching policy.
    const allowPaths = allPaths.filter(p => rules[p].some(c => c !== 'deny'));

    // Sort paths from highest priority to lowest
    const sortedAllowPaths = allowPaths.sort(comparePathPriority);

    let isAllowed = Z3.mk_false(ctx);

    // Iterate from highest to lowest priority, creating a nested if-then-else expression.
    for (const path of sortedAllowPaths) {
        const pathMatches = Z3.mk_seq_in_re(ctx, inputPath, buildRegexFromPath(ctx, path));
        const capabilitiesMatch = buildCapabilitiesMatch(ctx, inputCap, rules[path]);

        isAllowed = Z3.mk_ite(ctx, pathMatches, capabilitiesMatch, isAllowed);
    }

    // Final logic: access is granted if it is allowed AND it is not denied.
    return Z3.mk_and(ctx, [isAllowed, Z3.mk_not(ctx, isDenied)]);
  }

  async function checkPrivilegeEscalation(currentRules, newRules): Promise<PolicyCheckResult> {
    // Create context
    const cfg = Z3.mk_config();
    const ctx = Z3.mk_context(cfg);

    // Create string variables
    const inputPath = Z3.mk_const(ctx, Z3.mk_string_symbol(ctx, "path"), Z3.mk_string_sort(ctx));
    const inputCap = Z3.mk_const(ctx, Z3.mk_string_symbol(ctx, "cap"), Z3.mk_string_sort(ctx));

    // Create solver
    const solver = Z3.mk_solver(ctx);
    Z3.solver_inc_ref(ctx, solver);

    // Build policy matches
    const currentPolicy = buildPolicyMatch(ctx, inputPath, inputCap, currentRules);
    const newPolicy = buildPolicyMatch(ctx, inputPath, inputCap, newRules);

    const z3PolicyAst = {
      currentPolicyAst: Z3.ast_to_string(ctx, currentPolicy),
      newPolicyAst: Z3.ast_to_string(ctx, newPolicy)
    }

    // Add constraint: NOT current_policy AND new_policy
    Z3.solver_assert(ctx, solver,
      Z3.mk_and(ctx, [
           Z3.mk_not(ctx, currentPolicy),
           newPolicy
        ]
      )
    );

    // Check for satisfiability
    const result = await Z3.solver_check(ctx, solver);

    if (result === Z3_lbool.Z3_L_TRUE) {
      // Get model
      const model = Z3.solver_get_model(ctx, solver);
      Z3.model_inc_ref(ctx, model);

      // Get example path and capability values from model
      const pathDecl = Z3.mk_func_decl(ctx, Z3.mk_string_symbol(ctx, "path"), [], Z3.mk_string_sort(ctx));
      const capDecl = Z3.mk_func_decl(ctx, Z3.mk_string_symbol(ctx, "cap"), [], Z3.mk_string_sort(ctx));

      const pathValue = Z3.model_get_const_interp(ctx, model, pathDecl);
      const capValue = Z3.model_get_const_interp(ctx, model, capDecl);

      const examplePath = Z3.get_string(ctx, pathValue);
      const exampleCapability = Z3.get_string(ctx, capValue);

      Z3.model_dec_ref(ctx, model);
      Z3.solver_dec_ref(ctx, solver);

      // Cleanup
      Z3.del_context(ctx);

      return {
        result: true,
        path: examplePath,
        capability: exampleCapability,
        z3: z3PolicyAst
      };
    } else {
      Z3.solver_dec_ref(ctx, solver);

      // Cleanup
      Z3.del_context(ctx);

      return { result: false, path: null, capability: null, z3: z3PolicyAst };
    }
  }

  async function testAndPrint(currentRules, newRules) {
    const resultWithDeny = await checkPrivilegeEscalation(currentRules, newRules);

    if (resultWithDeny.result) {
      console.log("Privilege escalation detected!");
      console.log(`Example path: ${resultWithDeny.path}`);
      console.log(`Example capability: ${resultWithDeny.capability}`);
    } else {
      console.log("No privilege escalation detected.");
    }
  }

  // Demo usage
  async function runDemo() {

    // Additional test with deny capability
    console.log("\nTesting with deny capability...");
    await testAndPrint({
      "secret/users": ["read"],
      "secret/posts/*": ["read", "write"],
      "secret/posts/admin": ["deny"],
    }, {
      "secret/users": ["read"],
      "secret/posts/*": ["read", "write"],
      "secret/posts/admin": ["read"]
    });

     // Additional test with deny capability no privilege escalation
    await testAndPrint({
      "secret/users": ["read"],
      "secret/posts/*": ["read", "write"],
      "secret/posts/admin": ["deny"],
    }, {
      "secret/users": ["read"],
      "secret/posts/*": ["read", "write"],
      "secret/posts/admin": ["deny"]
    });

     // Additional test with deny capability no privilege escalation
    await testAndPrint({
      "secret/users": ["read"],
      "secret/posts/*": ["read", "write"],
      "secret/posts/admin": ["deny"],
    }, {
      "secret/users": ["read"],
      "secret/posts/*": ["read", "write"],
      "secret/posts/admin": ["deny"],
      "secret/posts/ad": ["read"]
    });

  }

  return {
    runDemo,
    checkPrivilegeEscalation
  };
}

function hclPathsToMap(hclPaths) {
  const paths = {};

  Object.entries(hclPaths)
      .forEach(([key, value] : [string, any]) => {
    paths[key] = value[0].capabilities;
  })

  return paths;
}

export function EscalationPolicyChecker() {
  const [checker, setChecker] = useState<{checkPrivilegeEscalation?: any}>({})
  const [isLoading, setIsLoading] = useState(true)
  const [isChecking, setIsChecking] = useState(false)
  const [error, setError] = useState<string>()

  const [currentPolicy, setCurrentPolicy] = useState<string>(exampleCurrentPolicy)
  const [newPolicy, setNewPolicy] = useState<string>(exampleNewPolicy)

  const [policyCheckResults, setPolicyCheckResults] = useState<PolicyCheckResult>()

  useEffect(() => {
    initZ3Checker()
        .then(s => {
          setIsLoading(false)
          setChecker(s)
        })
        .catch(e => {
          setIsLoading(false)
          setError(`Failed to load Z3 checker: ${e.message}`)
          console.error(e)
        })
  }, [])

  const handleCheck = async () => {
    if (!checker.checkPrivilegeEscalation) {
        setError("Checker is not yet available.");
        return;
    }

    setIsChecking(true);
    setPolicyCheckResults(undefined);
    setError(undefined);

    let currentPolicyObject = {}
    let newPolicyObject = {}

    try {
      currentPolicyObject = hclPathsToMap(hcl.parseToObject(currentPolicy)[0].path)
    } catch (e) {
      setError(`Invalid HCL in current policy: ${e.message}`)
      setIsChecking(false);
      return
    }

    try {
      newPolicyObject = hclPathsToMap(hcl.parseToObject(newPolicy)[0].path)
    } catch (e) {
      setError(`Invalid HCL in new policy: ${e.message}`)
      setIsChecking(false);
      return
    }

    try {
        const results = await checker.checkPrivilegeEscalation(currentPolicyObject, newPolicyObject);
        setPolicyCheckResults(results);
    } catch(e) {
        setError(`An error occurred during check: ${e.message}`);
    } finally {
        setIsChecking(false);
    }
  }


  if (isLoading) {
    return <div className="flex justify-center items-center p-8"><span className="loading loading-lg loading-spinner"></span></div>
  }

  const ResultAlert = () => {
    if (!policyCheckResults) return null;

    if (policyCheckResults.result) {
        return (
            <div role="alert" className="alert alert-warning">
                <div>
                    <h3 className="font-bold mt-0">Privilege Escalation Detected!</h3>
                    <div className="text-xs">An action is allowed under the new policy that was denied under the current one.</div>
                    <div className="text-sm mt-2">
                        Example: Granting <kbd className="kbd kbd-sm">{policyCheckResults.capability}</kbd> on path <kbd className="kbd kbd-sm">{policyCheckResults.path}</kbd>
                    </div>
                </div>
            </div>
        )
    }

    return (
        <div role="alert" className="alert alert-success">
            <div>
                <h3 className="font-bold mt-0">No Privilege Escalation Detected.</h3>
                <div className="text-xs">The new policy does not grant any new permissions.</div>
            </div>
        </div>
    )
  }

  return (
    <div className="p-4 md:p-8 max-w-6xl mx-auto">
        <div className="text-center mb-8">
            <h1 className="text-4xl font-bold">Vault Policy Escalation Checker Demo</h1>
            <p className="text-lg opacity-80 mt-2">Verify that changes to HashiCorp Vault policies do not grant unintended privileges.</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
            <div className="form-control">
                <label className="label">
                    <span className="label-text font-bold">Current Policy</span>
                </label>
                <textarea
                    className="textarea textarea-bordered h-72 font-mono text-sm"
                    value={currentPolicy}
                    onChange={event => setCurrentPolicy(event.target.value)}
                    placeholder="Enter current policy HCL..."
                />
            </div>
            <div className="form-control">
                <label className="label">
                    <span className="label-text font-bold">New Policy</span>
                </label>
                <textarea
                    className="textarea textarea-bordered h-72 font-mono text-sm"
                    value={newPolicy}
                    onChange={event => setNewPolicy(event.target.value)}
                    placeholder="Enter new policy HCL..."
                />
            </div>
        </div>

        <div className="text-center mb-6">
            <button className="btn btn-primary btn-wide" onClick={handleCheck} disabled={isChecking}>
                {isChecking && <span className="loading loading-spinner"></span>}
                Check for Escalation
            </button>
        </div>

        <div className="space-y-4">
            {error &&
                <div role="alert" className="alert alert-error">
                    <svg xmlns="http://www.w3.org/2000/svg" className="stroke-current shrink-0 h-6 w-6" fill="none" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                    <span>
                        <h3 className="font-bold">Error</h3>
                        <div className="text-xs">{error}</div>
                    </span>
                </div>
            }
            <ResultAlert />
        </div>

        {policyCheckResults && (
            <div className="collapse collapse-arrow border border-base-300 bg-base-200 mt-8">
                <input type="checkbox" />
                <div className="collapse-title text-xl font-medium">
                    Advanced Details
                </div>
                <div className="collapse-content">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <h3 className="font-bold mb-2">Current Policy (Z3 AST)</h3>
                            <pre className="bg-base-100 p-2 rounded-md text-xs overflow-x-auto"><code>{policyCheckResults.z3.currentPolicyAst}</code></pre>
                        </div>
                        <div>
                            <h3 className="font-bold mb-2">New Policy (Z3 AST)</h3>
                            <pre className="bg-base-100 p-2 rounded-md text-xs overflow-x-auto"><code>{policyCheckResults.z3.newPolicyAst}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
        )}
    </div>
  )

}