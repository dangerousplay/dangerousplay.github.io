---
title: "How to prevent Vault privilege escalation?"
description: "How can we trust that the policies won't have unintended, dangerous consequences tomorrow?"
pubDate: "Jul 28 2025"
heroImage: "/posts/heap_sort_hero.webp"
badge: "Security"
---

How can we be certain that Hashicorp Vault holding precious information is truly secure?
How can we trust that the policies won't have unintended, dangerous consequences tomorrow?

The answer, lies not in hope, but in proof. 
Not in guesswork, but in logic. 
Today, I would like to take you on a journey into a world where we can use the pristine power of mathematics to verify our work and build systems that are provably trustworthy. 
We will explore a beautiful concept called **Satisfiability Modulo Theories (SMT)** and use it to solve a very real-world challenge: securing HashiCorp Vault policies by denying privilege escalation.

### A Conversation with an Oracle of Logic: Meet Z3

Imagine you have access to an oracle. 
This oracle doesn't predict the future, but it can tell you one thing with absolute certainty: whether a set of logical statements can be true at the same time. 
This is the essence of an SMT solver. 
It's a "truth-seeking machine."

We'll be using a friendly and powerful SMT solver from Microsoft called **Z3**. 
Let's start with a simple conversation. 
Imagine we tell Z3:

> "Oh, wise Z3, I am thinking of two numbers, `x` and `y`. All I know is that `x + y = 20`, and also that `x` must be greater than `15`."

Can we find such numbers? Let's ask Z3 in its native tongue (Python).

```python
import z3

# Declare our two unknown numbers
x = z3.Int('x')
y = z3.Int('y')

# Create our solver, our oracle
solver = z3.Solver()

# Add our statements (constraints)
solver.add(x + y == 20)
solver.add(x > 15)

# Ask the oracle if a solution exists
print(solver.check()) 

# If a solution exists, ask for an example
if solver.check() == z3.sat:
    print(solver.model())
```


Z3 will reply:
`sat`
`[y = 4, x = 16]`

The word `sat` is short for "satisfiable." 
It means, "Yes, a world exists where all your statements are true." 
The model `[y = 3, x = 17]` is a concrete example from that world.

Now, what if we add one more rule: `y` must also be greater than `15`?

```python
# ... (previous code)
solver.add(y > 15) # Our new, impossible constraint

print(solver.check())
```


Z3 will now reply: `unsat`. 
It has mathematically proven that no such numbers can possibly exist. 
This power to prove both the possible and the impossible is what makes Z3 so profound.

### From Numbers to Paths: The Language of Vault

Now, how does this connect to securing Vault? 
Vault policies control access based on paths, like file paths on a computer. 
For example, a policy might grant access to `secret/app/db`.

The challenge arises with Vault's powerful wildcards:
- `+` matches a single path segment. `secret/+/db` would match `secret/app/db` but not `secret/app/v1/db`.
- `*` matches anything, even multiple segments. `secret/app/*` would match both `secret/app/db` and `secret/app/db/table`.

For a human, reviewing dozens of these rules can be bewildering. 
For Z3, it's just another logical puzzle. 
We can translate these path patterns into Z3's language of regular expressions.

Let's see how. 
We can write a small translator function. 
Don't worry about the details of the code; focus on the beautiful transformation from a policy string into a logical object.

```python
import z3
import re
from z3 import InRe, Re, Range, String, StringVal

def vault_path_to_z3_regex(path: str) -> z3.ReRef:
    """Converts a Vault path string into a Z3 regular expression."""
    # The '*' wildcard translates to '.*' in regex (any character, any number of times)
    # The '+' wildcard is trickier: it means 'any characters except a slash'
    
    re_parts = []

    def wildcard_ranges():
      return [
          Range('a', 'z'), Range('A', 'Z'), Range('0', '9'),
          Re(StringVal('-')), Re(StringVal('_')), Re(StringVal('.'))
      ]

    for part in re.split(r'([+]|\*$)', path):
        if part == '*':
            wildcard_regex = z3.Star(z3.Union(*wildcard_ranges(), Re(StringVal('/'))))
            re_parts.append(wildcard_regex)
        elif part == '+':
            re_parts.append(z3.Plus(z3.Union(*wildcard_ranges())))
        else:
            re_parts.append(Re(StringVal(part)))

    if len(re_parts) < 2:
        return re_parts[0]

    return z3.Concat(re_parts)

# Example Usage:
path_pattern = "secret/app/*"
z3_regex = vault_path_to_z3_regex(path_pattern)

print(f"The Vault path '{path_pattern}' becomes the Z3 regex: {z3_regex}")
```


Now Z3 understands what `secret/app/*` means. 
We can ask it questions! 
For example: "Does the path `secret/app/db` match the pattern `secret/app/*`?"

```python
# Declare an unknown string variable for the path we are checking
input_path = z3.String('input_path')

# Create the constraint
path_matches_pattern = z3.InRe(input_path, z3_regex)

# Ask Z3 if our example 'secret/app/db' satisfies the constraint
solver = z3.Solver()
solver.add(path_matches_pattern)
solver.add(input_path == z3.StringVal("secret/app/db"))

print(solver.check()) # This will print 'sat'
```


### The Ghost in the Machine: Finding Privilege Escalation

Here is the heart of our exploration. 
**Privilege escalation** happens when a change to a policy accidentally grants *more* access than intended. 
For example, a developer might want to add a new, specific rule but uses a broad wildcard by mistake.

How can we find this "ghost in the machine"? We can ask Z3 a very precise, philosophical question:

> **"Wise Z3, can you find me a single path that is ALLOWED by the NEW policy, but was DENIED by the OLD policy?"**

If Z3 says `sat` and gives us an example, we have found a privilege escalation!

Let's translate this into Z3's logic.

- `new_policy` = A path is allowed by the new rules.
- `old_policy` = A path is allowed by the old rules.
- `Not(old_policy)` = A path is denied by the old rules.

Our query to Z3 is: `And(new_policy, Not(old_policy))`

Let's try it with a real example.

- **Old Policy:** Access is granted to `secret/app/prod` only.
- **New Policy:** Access is granted to `secret/app/*`.

```python
# Our unknown input path
input_path = z3.String('input_path')

# 1. Define the old and new policies in Z3's language
old_policy_regex = vault_path_to_z3_regex("secret/app/prod")
new_policy_regex = vault_path_to_z3_regex("secret/app/*")

old_policy_match = z3.InRe(input_path, old_policy_regex)
new_policy_match = z3.InRe(input_path, new_policy_regex)

# 2. Formulate our philosophical question
escalation_found = z3.And(new_policy_match, z3.Not(old_policy_match))

# 3. Ask Z3
solver = z3.Solver()
solver.add(escalation_found)

print(f"Checking for escalation... {solver.check()}")

if solver.check() == z3.sat:
    print("Escalation detected! Here is an example:")
    print(solver.model())
```


Z3 will reply:
`Checking for escalation... sat`
`Escalation detected! Here is an example:`
`[input_path = "secret/app/d"]`

Look at that! Z3 didn't just tell us there was a problem; it gave us a *concrete example*. 
The path `secret/app/d` (and many others like `secret/app/dev`) is now allowed where it wasn't before. 
We have found the ghost.


### Completing the Picture: Paths and Capabilities

Our logic can be made even richer. Vault policies have two parts: the `path` and the `capabilities` (like `read`, `write`, `delete`). 
A user needs both to match.

Let's expand our model to check for an escalation where a user is granted a new capability on an existing path.

- **Old Policy:** `secret/app/db` -> `["read"]`
- **New Policy:** `secret/app/db` -> `["read", "write"]`

The question is the same, but our definition of "policy" is now more complete.

```python
# Declare unknown inputs for path and capability
input_path = z3.String('path')
input_cap = z3.String('cap')

# --- Old Policy Definition ---
# Path must be 'secret/app/db' AND capability must be 'read'
old_policy_match = z3.And(
    input_path == "secret/app/db",
    input_cap == "read"
)

# --- New Policy Definition ---
# Path must be 'secret/app/db' AND capability must be 'read' OR 'write'
new_policy_match = z3.And(
    input_path == "secret/app/db",
    z3.Or(
        input_cap == "read",
        input_cap == "write"
    )
)

# --- The Escalation Check ---
solver = z3.Solver()
solver.add(z3.And(new_policy_match, z3.Not(old_policy_match)))

print(f"Checking for escalation... {solver.check()}")
if solver.check() == z3.sat:
    print("Escalation detected! Here is the exact path and capability:")
    print(solver.model())
```


And Z3, our faithful oracle, will reveal the truth:
`Checking for escalation... sat`
`Escalation detected! Here is the exact path and capability:`
`[cap = "write", path = "secret/app/db"]`

It has precisely identified the escalation: the `write` capability was added to the `secret/app/db` path.

Examples of more complex policies that it can correctly identify privilege escalation:
```python
# Test case: Escalation - more specific wildcard in new rules
(
        {"secret/+/db": ["read"]},
        {"secret/app/db": ["read", "write"]},
        True
),

# Test case: No escalation - more restrictive rules
(
        {"secret/app/*": ["read"]},
        {"secret/app/db": ["read"]},
        False
),

# Test case: Escalation - wider wildcard
(
        {"secret/app/+": ["read"]},
        {"secret/app/*": ["read"]},
        True
),

# Test case: Complex escalation - multiple rules
(
        {
            "secret/app/db": ["read"],
            "secret/app/logs": ["read", "write"]
        },
        {
            "secret/app/db": ["read", "write"],
            "secret/app/logs": ["read", "write"]
        },
        True
),
```

You can see more examples of privilege escalation in [escalation tests](https://github.com/dangerousplay/vault-policy-checker/blob/master/python-poc/test_escalation.py)

All the code was published on Github repository [dangerousplay/vault-policy-checker](https://github.com/dangerousplay/vault-policy-checker)

### Future Work

- Integration with HashiCorp Vault API for direct policy extraction
- GUI for visualizing policy coverage and potential violations

### A More Hopeful Horizon

We began with a question of trust, and using pure logic we found an answer to a complex problem that was proved using math.
We can proof that the new policy does not give more privileges than the current one removing any scenario for privilege escalation.
Which is truly amazing considering how difficult it would be to proof the logic of an algorithm to do the same without using SMT.

Have a wonderful day, shine bright ^^