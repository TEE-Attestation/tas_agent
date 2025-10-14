# Contributing to TAS

Thank you for your interest in contributing! Please follow the guidelines below to ensure a smooth contribution process.

---

## How to Contribute

All contributions are accepted via **pull requests** on GitHub. Please submit your pull requests to this repository: [https://github.com/TEE-Attestation/tas_agent](https://github.com/TEE-Attestation/tas_agent).

By contributing, you agree that all code submissions fall under the terms of the **MIT License** (see the [LICENSE](./LICENSE.md) file). Additionally, all commits must be **signed off**.

---

## Patch Guidelines

### Format
- **Subject Line**: Start each patch with a short description of the change, followed by a colon.  
   Example: `Fix: Corrected memory leak in module X`.
- **Detailed Description**: Include a detailed explanation of what the change does and, if applicable, why it is necessary.

### Signed-off-by Tag
- Every patch must include a `Signed-off-by` tag, which can be added using the `git commit -s` command.
- If multiple contributors worked on a patch, use the `Co-developed-by` tag to credit developers.  Every `Co-developed-by` must be immediately followed by a `Signed-off-by` of the associated co-author. **Everyone that developed the patch must sign-off**. 

Example of a patch submitted by the From: author:
```
<changelog or description>

Co-developed-by: First Co-Author <first@example.org>
Signed-off-by: First Co-Author <first@example.org>
Co-developed-by: Second Co-Author <second@example.org>
Signed-off-by: Second Co-Author <second@example.org>
Signed-off-by: From Primary Author <primary@example.org>

```


### Developer Certificate of Origin
By adding the `Signed-off-by` tag, you confirm that your contribution complies with the [Developer Certificate of Origin](https://developercertificate.org/).  
The **name and email** in the `Signed-off-by` tag must match the **Author** field of the patch.

---

### Coding Style

- **Code Formatting**: tas_agent uses `rustfmt`, `cargo` and `clippy` to enforce a consistent code style. We provide a [pre-commit](https://pre-commit.com/) configuration to enforce the code style locally. Our CI will check if the code is formatted correctly. Refer to the [pre-commit](https://pre-commit.com/) website for installation and usage instructions. <!--Ensure you use the versions specified in our [.pre-commit-config.yaml](.pre-commit-config.yaml). -->

   For documentation guidelines consult https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html

- **No Warnings**: Your changes must not introduce new warnings during the build process.

### Squash Commits
If your pull request contains multiple commits (e.g., due to revisions during the review process), please squash your commits into one after receiving approval. This keeps the project history clean and easy to follow.