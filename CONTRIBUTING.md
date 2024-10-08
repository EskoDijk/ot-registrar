# Contributing to OT Registrar

## Contributor License Agreement (CLA)

Contributions to this project must be accompanied by a Contributor License Agreement. You (or your employer) retain the copyright to your contribution; this simply gives us permission to use and redistribute your contributions as part of the project. Head over to <https://cla.developers.google.com> to see your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one (even if it was for a different project), you probably don't need to do it again.

## Code of Conduct

Help us keep OpenThread open and inclusive.  Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Bugs

If you find a bug in the source code, you can help us by [submitting a GitHub Issue](https://github.com/EskoDijk/ot-registrar/issues/new). Even better, you can [submit a Pull Request](#submitting-a-pull-request) with a fix.

## New features

You can request a new feature by [submitting a GitHub Issue](https://github.com/EskoDijk/ot-registrar/issues/new).

If you would like to implement a new feature, please consider the scope of the new feature:

* *Large feature* — [Submit a GitHub Issue](https://github.com/EskoDijk/ot-registrar/issues/new) with your proposal so that the community can review and provide feedback first. Early feedback helps to ensure your proposal is accepted by the community, better coordinate our efforts, and minimize duplicated work.

* *Small feature* — Can be implemented and directly [submitted as a Pull Request](#submitting-a-pull-request) without a proposal.

## Contributing code

The OpenThread Project follows the "Fork-and-Pull" model for accepting contributions.

### Initial setup

Setup your GitHub fork and continuous integration services:

1. Fork the [OT Registrar repository](https://github.com/EskoDijk/ot-registrar) by clicking **Fork** on the web UI.
2. Enable GitHub CI by logging into your GitHub account and enabling it on your newly created fork. We use CI for Linux-based continuous integration checks. All contributions must pass these checks to be accepted.

Setup your local development environment:

```bash
# Clone your fork
git clone https://<username>@github.com/EskoDijk/ot-registrar.git

# Configure upstream alias
git remote add upstream https://<username>@github.com/EskoDijk/ot-registrar.git
```

### Submitting a pull request

#### Branch

For each new feature, create a working branch:

```bash
# Create a working branch for your new feature
git branch --track <branch-name> origin/main

# Checkout the branch
git checkout <branch-name>
```

#### Create commits

```bash
# Add each modified file you'd like to include in the commit
git add <file1> <file2>

# Create a commit
git commit
```

This will open up a text editor where you can craft your commit message.

#### Upstream sync and clean up

Prior to submitting your pull request, it's good practice to clean up your branch and make it as simple as possible for the original repo's maintainer to test, accept, and merge your work.

If any commits have been made to the upstream main branch, you should rebase your development branch so that merging it will be a simple fast-forward that won't require any conflict resolution work.

```bash
# Fetch upstream main and merge with your repo's main branch
git checkout main
git pull upstream main

# If there were any new commits, rebase your development branch
git checkout <branch-name>
git rebase main
```

At this point, it might be useful to squash some of your smaller commits down into a small number of larger more cohesive commits. You can do this with an interactive rebase:

```bash
# Rebase all commits on your development branch
git checkout
git rebase -i main
```

This will open up a text editor where you can specify which commits to squash.

#### Coding conventions and style

OT Registrar uses most of the [Google Java Style](https://google.github.io/styleguide/javaguide.html) at this moment. The reason for not using the full set of guidelines is that it introduces a very narrow line width (100), which makes code hard to read on normal-size desktop monitors used for coding that can easily handle long line lengths.
For an IDE, the XML file for this style can be [downloaded](https://github.com/google/styleguide) and applied and the line width increased to 200.

#### Push and test

```bash
# Checkout your branch
git checkout <branch-name>

# Push to your GitHub fork:
git push origin <branch-name>
```

This will trigger Github Continuous Integration (CI) checks. You can view the results in the respective services.

#### Submit the pull request

Once you've validated the CI results, go to the page for your fork on GitHub, select your development branch, and click the **Pull Request** button. If you need to make any adjustments to your pull request, push the updates to GitHub. Your pull request will automatically track the changes on your development branch and update.
