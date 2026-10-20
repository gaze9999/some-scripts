# Public content checks

Use Python 3.10+ and Git. Enable the versioned hooks in each clone after checking any existing `core.hooksPath`:

```sh
git config --local core.hooksPath .githooks
python tools/check-public-content.py --index
python tools/check-public-content.py --history
python -m unittest discover -s tests -p test_public_content.py
```

`pre-commit` checks staged bytes, including files whose working copy was subsequently changed. `pre-push` checks the complete ancestry and annotations of every outgoing branch or tag. History checks require a full clone and include detached HEAD. CI runs the same history check and regression tests on pushes and pull requests.

The guard rejects PEM private-key markers, standalone RSA/EC/PKCS#8 DER structures, signing-key filenames, CRX packages and absolute Windows personal/workspace roots. It checks binary blobs and common UTF-16/32, JSON, URL and HTML encodings. Diagnostics contain object IDs and categories, never matched content. Public certificates, public keys and generic `PROJECT_PATH` or `C:/path/to/project` examples remain allowed.

Keep signing material outside the repository. Use explicit project arguments and relative scopes rather than local company paths. Never reuse an exposed signing key. Review generated archives separately; this focused check is not an exhaustive secret classifier.

Repository policy: require the `public-content` GitHub Actions check on `main`. Push a working branch, wait for its check to pass, then fast-forward `main` to that exact commit. Disallow rewrites/deletion of protected branches and updates/deletion of existing tags through repository rules. Verify these server settings when restoring or transferring the repository. New clones must enable hooks locally; CI and GitHub secret push protection remain separate controls.
