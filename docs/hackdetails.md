​I am going to the truefoundry hackathon:

Ideas:

Pick a job worth handing to an agent such as a cloud cost cleanup, a migration rehearsal, a release captain, a support ticket resolver, an access reviewer, or a full runbook executor, and build it on TrueForge. Every submission needs to show the harness actually doing the work: a real tool reached, code run in a sandbox, and a pause before anything irreversible happens. 

Reach real systems. Run real code. Stop before it hurts.
A model that answers questions is a feature. A model that opens the pull request, runs the migration, or revokes the access key is something else entirely — and the distance between the two is not a better prompt. It is plumbing.
Acting on the world takes three things a chat window never needed, and every one of them is infrastructure rather than intelligence. That plumbing is the theme. Pick a job in any domain that is genuinely worth handing to an agent, and build the thing that does it end to end.
REQUIREMENT 01
It has to reach something real
Your database, your repo, your cloud account, your ticket queue. Connected over MCP, with real credentials and real consequences — not a mocked function returning fixture data.
REQUIREMENT 02
It has to run what it writes
An agent that reasons about code but cannot execute it is guessing. Generated code needs somewhere to actually run — isolated, disposable, and unable to damage anything when it is wrong.
REQUIREMENT 03
It has to know when to stop
Some actions cannot be taken back: the email sends, the row drops, the key is revoked. The agent should pause at that line and wait for a person, every time, and make it obvious what it is about to do.
The layer that handles all three sits between the model and everything it touches, and building it yourself would eat the whole day. TrueForge is an open-source one: MCP tools, sandboxed execution, approval checkpoints, subagents, and sessions that survive a reconnect. You write the agent; the harness does the machinery. TrueFoundry's AI gateway is there too if you want budgets, rate limits, and traces without touching your agent code — useful, but not required to win anything.

Starting points, not categories. Any domain is fair game — what matters is that the agent reaches something real and has a line it will not cross alone. Each of these has one.
01 · EASIEST START
Cloud cost janitor
Hunts down idle instances, orphaned volumes, and forgotten load balancers, works out what they cost you a month, and drafts a teardown plan you can read before anything disappears.
REACHES: your cloud billing + infra APIsGATE: deleting a resource
02 · DATA
Migration rehearsal agent
Takes a schema change, restores a copy into a sandbox, runs the migration there, diffs what actually happened to the rows, and reports back before it goes anywhere near the real database.
REACHES: your databaseGATE: applying to production
03 · SHIPPING
Release captain
Reads every commit since the last tag, runs the test suite in a sandbox, writes release notes a human would actually publish, then holds at the one step you cannot undo.
REACHES: GitHub + a package registryGATE: tagging and publishing
04 · SUPPORT
Ticket resolver
Picks up a bug report, tries to reproduce it in a sandbox, and comes back with either a patch and a draft reply or an honest "could not reproduce, here is what I tried".
REACHES: Linear, Jira, or ZendeskGATE: replying to the customer
05 · SECURITY
Access reviewer
Walks your IAM roles and service accounts, finds the permissions nobody has used in ninety days, and proposes a least-privilege diff with the blast radius of each revocation spelled out.
REACHES: your identity providerGATE: revoking access
06 · HERO PROJECT
Runbook executor
Reads a runbook written for a human and actually executes it, step by step, doing the reversible parts itself and stopping at every step that changes the world. The hardest of these, and the most useful.
REACHES: your infrastructureGATE: every destructive step

Five things. The first one decides whether a project qualifies at all — if it would work just as well as a text box, it is not this hackathon.
- An agent running on TrueForge, with the harness visibly doing the work: a real tool reached, code executed in the sandbox, a pause before something irreversible.
- One job, finished. Seven hours is short. One narrow task done end to end beats three half-built features every time.
- The approval moment in your demo. Show us where the code ran and show us the agent stopping to ask. This is the part everyone forgets to film.
- A public repo with a README that works on someone else's laptop. Note which AI assistants you used while building.
- Only what is yours to connect. Your accounts, your data, your keys — and none of those keys in the repo or the demo video.

Published up front so you can build against it. Every submission is scored on all five, out of 100.
30
The harness is doing the workThis is the one that decides whether you qualify. A judge has to watch TrueForge reach a real tool, run generated code in the sandbox, and hold for a person. An agent that is really a prompt with a nice wrapper scores near zero here regardless of how good the rest is.
25
It actually runsWorking software, not a deck. Someone who has never seen the project should be able to clone it, follow the README, and get it going on their own laptop. Narrow scope that works scores above broad scope that doesn't.
20
Where it stopsWhich actions did you decide the agent may never take alone, and can you defend the line you drew? We look at what is sandboxed, what is gated, how clearly the agent explains what it is about to do, and how small the damage would be if it got something wrong.
15
A job worth handing overWould a real person actually delegate this, and is it an interesting thing to delegate? Solving a chore someone genuinely has beats an impressive demo of nothing in particular.
10
Demo clarityFive minutes to show the job, the agent doing it, and where the harness fits. Judges will ask you to explain your own architecture, so be able to.
 
Desc:
​TrueForge is MIT-licensed and runs locally with one command, so you can start today: 
​npx @truefoundry/trueforge 
[https://github.com/truefoundry/trueforge](https://github.com/truefoundry/trueforge)


