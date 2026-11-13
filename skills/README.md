# Claude Code skills for pgard

Three skills that teach an assistant to use the installed `pgard` CLI safely:

- `pgard-scan`: run a code scan and report the result.
- `pgard-explain`: read a scan result and suggest fixes.
- `pgard-precommit`: run the pre-commit check and explain a block.

They were checked against pgard 0.3.0 and the commands in the repository `README.md`. They are not part of the published npm package.

## Install

Copy the skill folders you want:

```sh
# for one project
mkdir -p .claude/skills && cp -R skills/pgard-* .claude/skills/

# for every project of your user
mkdir -p ~/.claude/skills && cp -R skills/pgard-* ~/.claude/skills/
```

You also need `pgard` itself: `npm install -g pgard`, then `pgard doctor`.
