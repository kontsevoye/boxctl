# OpenWrt settings in the panel

Every user-facing boxctl option added to an OpenWrt UCI configuration must also
be manageable in the panel's Settings page in the same change. Include typed,
authenticated API read/write support, English and Russian labels, validation,
and the corresponding init-script wiring. Do not introduce options that can
only be configured over SSH.

UCI is the source of truth for these options. Read current values through UCI
and persist changes with UCI commit; do not maintain a second copy in the
panel's JSON settings. Preserve unrelated options and external pending changes.
Distinguish saved settings from the active process configuration and provide
an explicit application/restart flow when necessary.

Add coverage that checks all packaged user-facing UCI options have an API/UI
representation. Test validation, preservation of unrelated settings, failed
saves, and restart requirements. Verify UI changes in a local browser preview.
