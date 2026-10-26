# CLI usage

Command-line utility requires `click>=4.0` to be installed.

!!! warning
    This is a diagnostic tool, not a production authentication service.
    Its output includes password verifiers, private values and session keys.
    Run it only in a trusted environment; do not share, record or log its output.
    Successful command execution does not authenticate a peer: the CLI does not verify received proofs.
    Use the API's extended workflow for authentication.

## Hidden input

Pass `-` in place of a password, password verifier or `--private` value to enter it without echo.
This keeps the value out of command-line arguments, shell history and process listings.
Prompts and warnings go to stderr; results remain on stdout.
If terminal echo cannot be disabled, the command aborts instead of reading an exposed secret.

For example, create a verifier without putting the password in the command line:

```bash
srptools get-user-data-triplet --preset 2048 alice -
```

Enter a password consisting of the literal character `-` at the hidden prompt as well.
Inline secret arguments remain supported for existing diagnostic scripts, but emit a warning.
The hidden prompt protects input, not the diagnostic output described above.

## Diagnostic workflow

Use the values printed by each step in the later commands.
Values in angle brackets are placeholders for non-secret values from previous output; replace them before running.
Enter secret values at the hidden prompts. For session commands, `--private -` prompts for the private value first.

```bash
srptools get-user-data-triplet --preset 2048 alice -
srptools server get-private-and-public --preset 2048 alice -
srptools client get-private-and-public --preset 2048 alice -
srptools client get-session-data --preset 2048 --private - alice - <salt> <server-public>
srptools server get-session-data --preset 2048 --private - alice - <salt> <client-public>
```

All five commands accept `--preset` to select a prime and generator pair.
Use the same preset when creating the user data triplet and during all client and server session steps.
For example, pass `--preset 2048` to each command to use the 2048-bit group.
Selecting another preset does not convert an existing password verifier to that group.

Help is available:

```bash
srptools --help
```
