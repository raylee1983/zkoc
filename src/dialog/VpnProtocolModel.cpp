#include "VpnProtocolModel.h"

#include "common.h"
#include "logger.h"

VpnProtocolModel::VpnProtocolModel(QObject* parent)
    : QAbstractListModel(parent)
{
    loadProtocols();
}

int VpnProtocolModel::rowCount(const QModelIndex& parent) const
{
    Q_UNUSED(parent);

    return m_protocols.size();
}

QVariant VpnProtocolModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid()) {
        return QVariant();
    }

    const VpnProtocol protocol = m_protocols.at(index.row());

    switch (role) {
    case Qt::DisplayRole:
        return QVariant{ protocol.prettyName };
    case Qt::ToolTipRole:
        return QVariant{ protocol.description };
    case ROLE_PROTOCOL_NAME:
        return QVariant{ protocol.name };
    }

    return QVariant();
}

unsigned VpnProtocolModel::findIndex(const QString name)
{
    QList<VpnProtocol>::iterator i;

    for (i = this->m_protocols.begin(); i != this->m_protocols.end(); ++i) {
        if ((*i).name.compare(name) == 0) {
            return ((*i).index);
        }
    }

    Logger::instance().addMessage(QObject::tr("未知协议: ") + name);
    return 0;
}

void VpnProtocolModel::loadProtocols()
{
    struct oc_vpn_proto* protos = nullptr;
    unsigned i = 0;

    if (openconnect_get_supported_protocols(&protos) >= 0) {
        for (oc_vpn_proto* p = protos; p->name; ++p) {
            m_protocols.append({ i++, p->name, p->pretty_name, p->description });
        }
        openconnect_free_supported_protocols(protos);
    }
}
