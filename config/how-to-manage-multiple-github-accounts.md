---
title: "How to Manage Multiple GitHub Accounts on One Computer using SSH"
description: "A complete guide on setting up and switching between personal and work GitHub accounts using custom SSH configurations and IdentityFiles."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-07"
updated: "2026-04-07"
thumbnail: "/images/github-multiple-accounts.webp"
tags: [Git, GitHub, SSH, DevOps, Workflow]
keywords: ["Manage multiple GitHub accounts SSH", "SSH config for GitHub", "Switching between GitHub accounts", "Using different SSH keys for work and personal", "Git config user.email multiple accounts"]
---

# How to Manage Multiple GitHub Accounts on One Computer

**Managing Multiple GitHub Accounts with SSH Keys: A Step-by-Step Guide**

Working with multiple GitHub accounts? You’re not alone. Whether it’s for personal projects, work, or side hustles, switching between accounts can quickly become a hassle—especially when you want to avoid mixing up your commits or authentication. The solution? **Using separate SSH keys and aliases** to seamlessly manage multiple GitHub accounts on the same machine.

This guide will walk you through the process, from generating keys to configuring SSH and Git, so you can effortlessly switch between accounts without any conflicts.

![manage-multiple-accounts](/images/github-multiple-accounts.webp)

## Why Use Separate SSH Keys?

SSH keys allow you to authenticate with GitHub without typing your password every time. By using **separate keys for each account**, you ensure that:

- Commits and pushes are attributed to the correct account.
- You avoid authentication conflicts when switching between projects.
- You maintain security by isolating keys for personal and work accounts.

## Step 1: Generate Unique SSH Keys for Each Account

Start by creating a dedicated SSH key pair for each GitHub account using the `ed25519` algorithm (recommended for its balance of security and performance):

```bash
# Personal Account
ssh-keygen -t ed25519 -C "personal@email.com" -f ~/.ssh/id_ed25519_personal

# Work Account
ssh-keygen -t ed25519 -C "work@company.com" -f ~/.ssh/id_ed25519_work
```

Replace the email addresses with the ones associated with your GitHub accounts. When prompted for a passphrase, you can leave it empty or add one for extra security.

What’s Generated?
- `~/.ssh/id_ed25519_personal` (private key)
- `~/.ssh/id_ed25519_personal.pub` (public key)

- `~/.ssh/id_ed25519_work` (private key)
- `~/.ssh/id_ed25519_work.pub` (public key)


## Step 2: Add Public Keys to Your GitHub Accounts

Now, link each public key to its corresponding GitHub account.

### For Your Personal Account:
1. Display your public key:
   ```bash
   cat ~/.ssh/id_ed25519_personal.pub
   ```
2. Copy the output.
3. Log in to your **personal GitHub account**.
4. Go to **Settings → SSH and GPG keys → New SSH key**.
5. Paste the key, give it a name (e.g., "Personal Machine"), and save.

### For Your Work Account:
Repeat the process for your work account:
1. Display the public key:
   ```bash
   cat ~/.ssh/id_ed25519_work.pub
   ```
2. Copy the output.
3. Log in to your **work GitHub account**.
4. Add the key under **Settings → SSH and GPG keys**.

---

## Step 3: Configure SSH to Use the Right Key

Create or edit the SSH config file to map custom hostnames to your GitHub accounts:

```bash
nano ~/.ssh/config
```

Add the following configuration:

```plaintext
# Personal GitHub Account
Host github.com-personal
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_personal

# Work GitHub Account
Host github.com-work
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_work
```

Save the file (`Ctrl+O`, then `Enter`, then `Ctrl+X` in `nano`).

How Does This Work?
- `Host github.com-personal` and `Host github.com-work` are **aliases** you’ll use in your Git commands.
- SSH translates these aliases to `github.com` but uses the correct private key for authentication.

## Step 4: Clone Repositories with the Correct Alias

When cloning a repository, use the alias that matches the account you want to use:

### For Personal Projects:
```bash
git clone git@github.com-personal:username/personal-repo.git
```

### For Work Projects:
```bash
git clone git@github.com-work:company/work-repo.git
```


**Why Aliases Matter**
Without aliases, both accounts would default to the same SSH key (`~/.ssh/id_rsa` or `~/.ssh/id_ed25519`), causing conflicts. The aliases ensure SSH picks the right key for each account.


## Step 5: Set Git Identity per Project

To ensure commits are attributed to the correct account, configure Git’s user settings for each project:

```bash
# Navigate to your project directory
cd ~/projects/personal-repo

# Set personal account identity
git config user.email "personal@email.com"
git config user.name "Your Personal Name"
```

Repeat for work projects:
```bash
cd ~/projects/work-repo
git config user.email "work@company.com"
git config user.name "Your Work Name"
```


**Pro Tip:**
Use `git config --global` only if you want a default email/name for all projects. For multiple accounts, **per-project configuration is best**.


## Step 6: Verify SSH Authentication

Test that both keys work correctly:

```bash
ssh -T git@github.com-personal
ssh -T git@github.com-work
```

You should see messages like:
```
Hi username-personal! You've successfully authenticated...
Hi username-work! You've successfully authenticated...
```

## Troubleshooting: What If I Cloned with the Wrong Accoun**

No worries! Update the remote URL to use the correct alias:

```bash
git remote set-url origin git@github.com-work:username/work-repo.git
```

## Summary Table: Key Commands

| Action | Command |
|--------|---------|
| Generate key | `ssh-keygen -t ed25519 -C "email@example.com" -f ~/.ssh/id_ed25519_alias` |
| View public key | `cat ~/.ssh/id_ed25519_alias.pub` |
| Clone repo | `git clone git@github.com-alias:username/repo.git` |
| Set Git identity | `git config user.email "email@example.com"` |
| Test SSH | `ssh -T git@github.com-alias` |

## Final Notes
- Always use the correct host alias (`github.com-personal` or `github.com-work`) when cloning or pushing.
- Set Git’s user settings **per-project** to avoid mixing up commits.
- Use `ssh -T` to verify authentication for each account.

With this setup, you can switch between GitHub accounts effortlessly—no more login headaches or misattributed commits!

