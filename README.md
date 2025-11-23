# Fail2Ban Hybrid Manager

## Releases

- **[Latest Stable Release: v0.8](releases/v0.8/)**  
  Production-ready, optimized, idempotent setup (recommended for all new installations and upgrades).
- **[Legacy Release: v0.7.3](releases/v0.7.3/)**  
  For recovery, migration, or reference only. Use for rollback/compatibility if needed.

## Directory Structure

- `releases/v0.8/` — All scripts, documentation and configs for version 0.8 and above
- `releases/v0.7.3/` — Archive/legacy scripts, configs, old jail/filter files and recovery/upgrade tools for v0.7.3
- `.gitignore` — Project ignore rules (recommended: ignore .DS_Store, temp files)
- `README.md` — Main project navigation and quick start

## Quick Start

For a new installation or upgrade from older version:

```bash
cd releases/v0.8
sudo bash fail2ban_v0.8-setup-final.sh
source ~/.bashrc # Enable CLI aliases
sudo fail2ban-client status
```

For migration/rollback or reference:
- See [docs/MIGRATION.md](releases/v0.8/docs/MIGRATION.md)
- For legacy rescue tools or configs, see [releases/v0.7.3/](releases/v0.7.3/)

## Documentation

- [v0.8 Migration Guide](releases/v0.8/docs/MIGRATION.md)
- [v0.8 Features Guide](releases/v0.8/docs/FEATURES.md)
- Release guides, troubleshooting, performance metrics all available in `releases/v0.8/docs/`

## Best Practice

- Use the latest stable release at all times.
- Refer to legacy archive only for specific recovery/migration needs.
- All change history and previous versions are traceable in releases/ subdirectories and tags.
- For troubleshooting/support, open a GitHub issue or discussion.

---

**Note:**  
This repository is regularly cleaned and release-structured for clarity and maintainability.  
Legacy configs/scripts reside only in their dedicated archive/release folders.  
If you need help or want to contribute, open an issue or pull request!

