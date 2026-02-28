#include "NewProfileDialog.h"
#include "ui_NewProfileDialog.h"

#include "VpnProtocolModel.h"

#include "server_storage.h"

#include <QPushButton>
#include <OcSettings.h>
#include <QUrl>

#include <memory>

NewProfileDialog::NewProfileDialog(QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::NewProfileDialog)
{
    ui->setupUi(this);
    VpnProtocolModel* model = new VpnProtocolModel(this);
    ui->protocolComboBox->setModel(model);

    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setText(tr("保存并连接"));
    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setDefault(true);

    ui->buttonBox->button(QDialogButtonBox::Save)->setEnabled(false);
    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setEnabled(false);

    quick_connect = false;
}

NewProfileDialog::~NewProfileDialog()
{
    delete ui;
}

void NewProfileDialog::setQuickConnect()
{
    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setEnabled(true);
    ui->buttonBox->button(QDialogButtonBox::Save)->setVisible(false);
    ui->checkBoxCustomize->setVisible(false);
    ui->protocolComboBox->setFocus();
    this->quick_connect = true;
}

QString NewProfileDialog::urlToName(QUrl & url)
{
    if (url.port(443) == 443)
        return url.host();
    else
        return (url.host() + tr(":%1").arg(url.port(443)));
}

void NewProfileDialog::updateName(QUrl & url)
{
    ui->lineEditName->setText(urlToName(url));
}

void NewProfileDialog::setUrl(QUrl & url)
{
    updateName(url);
    ui->lineEditGateway->setText(url.toString());
}

QString NewProfileDialog::getNewProfileName() const
{
    return ui->lineEditName->text();
}

void NewProfileDialog::changeEvent(QEvent* e)
{
    QDialog::changeEvent(e);
    switch (e->type()) {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}

void NewProfileDialog::on_checkBoxCustomize_toggled(bool checked)
{
    if (checked == false) {
        QUrl url = QUrl::fromUserInput(ui->lineEditGateway->text());
        if (url.isValid()) {
            updateName(url);
        }

        ui->lineEditGateway->setFocus();
    } else {
        ui->lineEditName->setFocus();
    }
}

void NewProfileDialog::on_lineEditName_textChanged(const QString&)
{
    if (quick_connect == false)
        updateButtons();
}

void NewProfileDialog::on_lineEditGateway_textChanged(const QString& text)
{
    QUrl url(text, QUrl::StrictMode);
    if (ui->checkBoxCustomize->isChecked() == false && (url.isValid() || text.isEmpty())) {
        updateName(url);
    }

    updateButtons();
}

#define PREFIX "server:"
void NewProfileDialog::updateButtons()
{
    bool enableButtons{ false };
    if (ui->lineEditName->text().isEmpty() == false && ui->lineEditGateway->text().isEmpty() == false) {

        enableButtons = true;

        // TODO: refactor this too :/
        OcSettings settings;
        for (const auto& key : settings.allKeys()) {
            if (key.startsWith(PREFIX) && key.endsWith("/server")) {
                QString str{ key };
                str.remove(0, sizeof(PREFIX) - 1); /* remove prefix */
                str.remove(str.size() - 7, 7); /* remove /server suffix */
                if (str == ui->lineEditName->text()) {
                    enableButtons = false;
                    break;
                }
            }
        }
    }

    ui->buttonBox->button(QDialogButtonBox::Save)->setEnabled(enableButtons);
    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setEnabled(enableButtons);
}

void NewProfileDialog::on_buttonBox_clicked(QAbstractButton* button)
{
    if (quick_connect == false && ui->buttonBox->standardButton(button) == QDialogButtonBox::SaveAll) {
        emit connect();
    }
}

void NewProfileDialog::on_buttonBox_accepted()
{
    auto ss{ std::make_unique<StoredServer>() };
    ss->set_label(ui->lineEditName->text());
    ss->set_server_gateway(ui->lineEditGateway->text());
    ss->set_protocol_name(ui->protocolComboBox->currentData(ROLE_PROTOCOL_NAME).toString());
    ss->save();

    accept();
}
