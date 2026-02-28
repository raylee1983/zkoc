/*
 * Copyright (C) 2014 Red Hat
 *
 * This file is part of openconnect-gui.
 *
 * openconnect-gui is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "editdialog.h"
#include "VpnProtocolModel.h"
#include "common.h"
#include "server_storage.h"
#include "ui_editdialog.h"
#include <QFileDialog>
#include <QItemSelectionModel>
#include <QListWidget>
#include <QMessageBox>

#ifdef USE_SYSTEM_KEYS
extern "C" {
#include <gnutls/system-keys.h>
}
#endif

static int token_tab(int mode)
{
    // keep in sync with the indices of the QComboBox items in src/dialog/editdialog.ui
    switch (mode) {
    case OC_TOKEN_MODE_HOTP:
        return 0;
    case OC_TOKEN_MODE_TOTP:
        return 1;
    case OC_TOKEN_MODE_STOKEN:
        return 2;
    default:
        return -1;
    }
}

static int token_rtab[] = {
    // keep in sync with the indices of the QComboBox items in src/dialog/editdialog.ui
    OC_TOKEN_MODE_HOTP,  // [0]
    OC_TOKEN_MODE_TOTP,  // [1]
    OC_TOKEN_MODE_STOKEN // [2]
};

static int loglevel_tab(int mode)
{
    // keep in sync with the indices of the QComboBox items in src/dialog/editdialog.ui
    switch (mode) {
    case -1: //application default
        return 0;
    case PRG_ERR:
        return 1;
    case PRG_INFO:
        return 2;
    case PRG_DEBUG:
        return 3;
    case PRG_TRACE:
        return 4;
    default:
        return -1;
    }
}

static int loglevel_rtab[] = {
    // keep in sync with the indices of the QComboBox items in src/dialog/editdialog.ui
    -1,        // [0]
    PRG_ERR,   // [1]
    PRG_INFO,  // [2]
    PRG_DEBUG, // [3]
    PRG_TRACE  // [4]
};

void EditDialog::load_win_certs()
{
#ifdef USE_SYSTEM_KEYS
    QString prekey = ss->get_key_url();

    this->winCerts.clear();
    ui->loadWinCertList->clear();

    int ret = -1;
    gnutls_system_key_iter_t iter = nullptr;
    char* cert_url;
    char* key_url;
    char* label;
    int row = 0;
    int idx = -1;
    do {
        ret = gnutls_system_key_iter_get_info(&iter, GNUTLS_CRT_X509, &cert_url, &key_url, &label,
            nullptr, 0);
        if (ret >= 0) {
            win_cert_st st;
            QString l;
            if (label != nullptr)
                l = QString::fromUtf8(label);
            else
                l = QString::fromUtf8(cert_url);
            ui->loadWinCertList->addItem(l);
            if (prekey.isEmpty() == false) {
                if (QString::compare(prekey, QString::fromUtf8(key_url), Qt::CaseSensitive) == 0) {
                    ui->userCertEdit->setText(cert_url);
                    ui->userKeyEdit->setText(prekey);

                    idx = row;
                }
            }
            row++;

            st.label = l;
            st.key_url = QString::fromUtf8(key_url);
            st.cert_url = QString::fromUtf8(cert_url);
            this->winCerts.push_back(st);
        }
    } while (ret >= 0);

    if (idx != -1) {
        ui->loadWinCertList->setCurrentRow(idx);
        ui->loadWinCertList->item(idx)->setSelected(true);
    }
    gnutls_system_key_iter_deinit(iter);
#endif
}

EditDialog::EditDialog(QString server, QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::EditDialog)
    , ss(new StoredServer())
{
    ui->setupUi(this);

#ifdef _WIN32
    ui->interfaceNameEdit->setMaxLength(OC_IFNAME_MAX_LENGTH);
#endif

    VpnProtocolModel* model = new VpnProtocolModel(this);
    ui->protocolComboBox->setModel(model);

    if (ss->load(server) < 0) {
        QMessageBox::information(this,
            qApp->applicationName(),
            ss->m_last_err.isEmpty() ? tr("服务器信息加载失败") : ss->m_last_err);
    }

    ss->set_window(this);

    QString txt = ss->get_label();
    ui->nameEdit->setText(txt);
    if (txt.isEmpty() == true) {
        ui->nameEdit->setText(server);
    }
    ui->groupnameEdit->setText(ss->get_groupname());
    ui->usernameEdit->setText(ss->get_username());
    ui->gatewayEdit->setText(ss->get_server_gateway());
    ui->userCertHash->setText(ss->get_client_cert_pin());
    ui->caCertHash->setText(ss->get_ca_cert_pin());
    ui->batchModeBox->setChecked(ss->get_batch_mode());
    ui->minimizeBox->setChecked(ss->get_minimize());
    ui->useProxyBox->setChecked(ss->get_proxy());
    ui->disableUdpBox->setChecked(ss->get_disable_udp());
    ui->reconnectTimeoutSpinBox->setValue(ss->get_reconnect_timeout());
    ui->dtlsAttemptPeriodSpinBox->setValue(ss->get_dtls_reconnect_timeout());

    // Load the windows certificates
    load_win_certs();

    int type = ss->get_token_type();
    if (type >= 0) {
        ui->tokenBox->setCurrentIndex(token_tab(ss->get_token_type()));
        ui->tokenEdit->setText(ss->get_token_str());
    }

    ui->protocolComboBox->setCurrentIndex(model->findIndex(ss->get_protocol_name()));
    ui->interfaceNameEdit->setText(ss->get_interface_name());
    ui->vpncScriptEdit->setText(ss->get_vpnc_script_filename());

    type = loglevel_tab(ss->get_log_level());
    if (type != -1) {
        ui->loglevelBox->setCurrentIndex(type);
    }

    QString hash;
    ss->get_server_pin(hash);
    ui->serverCertHash->setText(hash);
}

EditDialog::~EditDialog()
{
    delete ui;
    delete ss;
}

QString EditDialog::getEditedProfileName() const
{
    return ss->get_label();
}

void EditDialog::on_buttonBox_accepted()
{
    if (ui->gatewayEdit->text().isEmpty() == true) {
        QMessageBox::information(this,
            qApp->applicationName(),
            tr("修改网关（如：vpn.example.com:443）"));
        return;
    }

    if (ui->nameEdit->text().isEmpty() == true) {
        QMessageBox::information(this,
            qApp->applicationName(),
            tr("修改连接名称（如：'智瞰VPN'）"));
        return;
    }

    if (ui->caCertEdit->text().isEmpty() == false) {
        if (ss->set_ca_cert(ui->caCertEdit->text()) != 0) {
            QMessageBox mbox;
            mbox.setText(tr("导入CA证书失败"));
            if (ss->m_last_err.isEmpty() == false)
                mbox.setInformativeText(ss->m_last_err);
            mbox.exec();
            return;
        } else {
            ui->caCertHash->setText(ss->get_ca_cert_pin());
        }
    }

    if (ui->userKeyEdit->text().isEmpty() == false) {
        if (ss->set_client_key(ui->userKeyEdit->text()) != 0) {
            QMessageBox mbox;
            mbox.setText(tr("导入用户key文件失败"));
            if (ss->m_last_err.isEmpty() == false)
                mbox.setInformativeText(ss->m_last_err);
            mbox.exec();
            return;
        }
    }

    if (ui->userCertEdit->text().isEmpty() == false) {
        if (ss->set_client_cert(ui->userCertEdit->text()) != 0) {
            QMessageBox mbox;
            mbox.setText(tr("导入用户证书失败"));
            if (ss->m_last_err.isEmpty() == false)
                mbox.setInformativeText(ss->m_last_err);
            mbox.exec();
            return;
        } else {
            ui->userCertHash->setText(ss->get_client_cert_pin());
        }
    }

    if (ss->client_is_complete() != true) {
        QMessageBox::information(this,
            qApp->applicationName(),
            tr("缺少密钥：已指定客户端证书!"));
        return;
    }
    ss->set_label(ui->nameEdit->text());
    ss->set_username(ui->usernameEdit->text());
    ss->set_server_gateway(ui->gatewayEdit->text());
    ss->set_batch_mode(ui->batchModeBox->isChecked());
    ss->set_minimize(ui->minimizeBox->isChecked());
    ss->set_proxy(ui->useProxyBox->isChecked());
    ss->set_disable_udp(ui->disableUdpBox->isChecked());
    ss->set_reconnect_timeout(ui->reconnectTimeoutSpinBox->value());
    ss->set_dtls_reconnect_timeout(ui->dtlsAttemptPeriodSpinBox->value());

    int type = ui->tokenBox->currentIndex();
    if (type != -1 && ui->tokenEdit->text().isEmpty() == false) {
        ss->set_token_str(ui->tokenEdit->text());
        ss->set_token_type(token_rtab[type]);
    } else {
        ss->set_token_str("");
        ss->set_token_type(-1);
    }

    ss->set_protocol_name(ui->protocolComboBox->currentData(ROLE_PROTOCOL_NAME).toString());
    ss->set_interface_name(ui->interfaceNameEdit->text());
    ss->set_vpnc_script_filename(ui->vpncScriptEdit->text());

    type = ui->loglevelBox->currentIndex();
    if (type == -1) {
        type = 0; //first entry is "application default"
    }
    ss->set_log_level(loglevel_rtab[type]);

    ss->save();
    this->accept();
}

void EditDialog::on_buttonBox_rejected()
{
    this->reject();
}

void EditDialog::on_userCertButton_clicked()
{
    QString filename = QFileDialog::getOpenFileName(this,
        tr("选择证书"), "",
        tr("证书文件 (*.crt *.pem *.der *.p12)"));

    // FIXME: check empty result
    ui->userCertEdit->setText(filename);
}

void EditDialog::on_userKeyButton_clicked()
{
    QString filename = QFileDialog::getOpenFileName(this,
        tr("选择Key文件"), "",
        tr("Key文件 (*.key *.pem *.der *.p8 *.p12)"));

    // FIXME: check empty result
    ui->userKeyEdit->setText(filename);
}

void EditDialog::on_caCertButton_clicked()
{
    QString filename = QFileDialog::getOpenFileName(this,
        tr("选择证书"), "",
        tr("证书文件(*.crt *.pem *.der)"));

    // FIXME: check empty result
    ui->caCertEdit->setText(filename);
}

void EditDialog::on_userCertClear_clicked()
{
    ss->clear_cert();
    ui->userCertEdit->clear();
    ui->userCertHash->clear();
}

void EditDialog::on_userKeyClear_clicked()
{
    ss->clear_key();
    ui->userKeyEdit->clear();
}

void EditDialog::on_caCertClear_clicked()
{
    ss->clear_ca();
    ui->caCertEdit->clear();
    ui->caCertHash->clear();
}

void EditDialog::on_serverCertClear_clicked()
{
    ss->clear_server_pin();
    ui->serverCertHash->clear();
}

void EditDialog::on_tokenClear_clicked()
{
    ui->tokenBox->setCurrentIndex(-1);
    ui->tokenEdit->clear();
}

void EditDialog::on_groupnameClear_clicked()
{
    ss->clear_groupname();
    ui->groupnameEdit->clear();
}

void EditDialog::on_loadWinCert_clicked()
{
    int idx = ui->loadWinCertList->currentRow();
    win_cert_st st;
    if (idx < 0 || this->winCerts.size() <= (unsigned)idx)
        return;

    st = this->winCerts.at(idx);
    ui->userCertEdit->setText(st.cert_url);
    ui->userKeyEdit->setText(st.key_url);
}

void EditDialog::on_groupnameEdit_textChanged(const QString& arg1)
{
    ui->groupnameClear->setEnabled(!arg1.isEmpty());
}

void EditDialog::on_caCertEdit_textChanged(const QString& arg1)
{
    ui->caCertClear->setEnabled(!arg1.isEmpty());
}

void EditDialog::on_serverCertHash_textChanged(const QString& arg1)
{
    ui->serverCertClear->setEnabled(!arg1.isEmpty());
}

void EditDialog::on_tokenEdit_textChanged(const QString& arg1)
{
    ui->tokenClear->setEnabled(!arg1.isEmpty());
}

void EditDialog::on_userCertEdit_textChanged(const QString& arg1)
{
    ui->userCertClear->setEnabled(!arg1.isEmpty());
}

void EditDialog::on_userKeyEdit_textChanged(const QString& arg1)
{
    ui->userKeyClear->setEnabled(!arg1.isEmpty());
}

void EditDialog::on_loadWinCertList_itemSelectionChanged()
{
    ui->loadWinCert->setEnabled(!ui->loadWinCertList->selectedItems().empty());
}

void EditDialog::on_resetWinCertSelection_clicked()
{
    ui->loadWinCertList->setCurrentRow(-1);

    on_userCertClear_clicked();
    on_userKeyClear_clicked();
}

void EditDialog::on_vpncScriptButton_clicked()
{
#ifdef Q_OS_WIN32
    QString filter = tr("Javascript Files (*.js)");
#else
    QString filter = nullptr;
#endif

    QString filename = QFileDialog::getOpenFileName(this,
        tr("选择vpnc脚本"),
        ui->vpncScriptEdit->text(),
        filter
    );

    if (! filename.isEmpty()) {
        filename = QDir::toNativeSeparators(filename);
        ui->vpncScriptEdit->setText(filename);
    }
}
