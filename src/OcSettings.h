#pragma once

#include <QObject>
#include <QSettings>

// This class is a thin wrapper over QSettings that ensures we retain
// compatibility with the existing settings even if we change the
// application name or the company name.
//
// Modify it when settings should become intentionally incompatible.
class OcSettings : public QSettings {
public:
    OcSettings() : QSettings("智瞰VPN团队", "智瞰VPN") { };
};
