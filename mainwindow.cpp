#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    session_key_file = "session_key";
    public_key_file = "public_key";
    message_file = "message";

    public_key_file_sign = "public_key_sign";
    hash_file_sign = "sign_file";
    message_file_sign = "message_sign";
}

MainWindow::~MainWindow()
{
    delete ui;
}

//СИМ

void MainWindow::on_pushButton_clicked()
{
  DWORD dwIndex=0;
  DWORD dwType;
  DWORD cbName;
  LPTSTR pszName;

  DWORD err;

  while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName))
  {
    if (!cbName)
      break;
    if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName)))
      return;
    if (!CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName))
    {
      err = GetLastError();
      ui->label_8->setText(QString::number(err));
      return;
    }
    ui->listWidget->addItem(QString("--------------------------------"));
    ui->listWidget->addItem(QString("Provider name: ") + QString::fromWCharArray(pszName));
    ui->listWidget->addItem(QString("Provider type: ") + QString::number(dwType));
    LocalFree(pszName);
  }
}

void MainWindow::on_pushButton_2_clicked()
{
  HCRYPTPROV hProv;
  HCRYPTKEY hKey;
  HCRYPTHASH hHash;

  DWORD err;

  // Получение контекста криптопровайдера
  if (!CryptAcquireContext(&hProv, NULL, NULL,PROV_RSA_FULL, NULL))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Cryptographic provider initialized");

  // Cоздание хеш-объекта
  if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Hash created");

  // Передача хешируемых данных хэш-объекту.

  std::string pass = ui->lineEdit->text().toStdString().c_str();
  DWORD count = pass.length();

  if(!CryptHashData(hHash, (BYTE*)(pass.c_str()), count, 0))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Hash data loaded");

  if(!CryptDeriveKey(hProv, CALG_RC4, hHash, NULL, &hKey))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Key Derived");

  std::wstring mess = ui->textEdit->toPlainText().toStdWString();
  count = mess.length()*2;

  if(!CryptEncrypt(hKey, 0, true, 0, (BYTE*)mess.c_str(), &count, mess.length()*2))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }

  ui->listWidget_2->addItem("Text Encrypted");
  ui->textEdit_2->setText(QString::fromStdWString(mess));

  std::wofstream fout;
  fout.open("op_enc_txt");
  if(fout.is_open())
  {
    fout << mess;
    ui->listWidget_2->addItem("File");
    fout.close();
  }

  ui->listWidget_2->addItem(CMDEND);
}

//АСИМ

void MainWindow::on_pushButton_3_clicked()
{
  HCRYPTKEY hKey_asym;

  DWORD err;

  // Получение контекста криптопровайдера
  if (!CryptAcquireContext(&hProv_asym_server, ui->lineEdit_2->text().toStdWString().c_str(), NULL,PROV_RSA_FULL, CRYPT_NEWKEYSET))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Cryptographic provider initialized");

  // Генерация ключа для тестирования
  if (!CryptGenKey(hProv_asym_server, AT_KEYEXCHANGE, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &hKey_asym))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Private/Public keys generated");

  ui->listWidget_2->addItem(CMDEND);
}

void MainWindow::on_pushButton_4_clicked()
{
  HCRYPTKEY hPublicKey;

  DWORD err;

  // Получение ключа для экспорта ключа шифрования
  if (!CryptGetUserKey(hProv_asym_server, AT_KEYEXCHANGE, &hPublicKey))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Public key is received");

  DWORD count = 0;

  // Получение размера массива, используемого для экспорта ключа
  if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, NULL, &count))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }

  // Инициализация массива, используемого для экспорта ключа
  BYTE* data = static_cast<BYTE*>(malloc(count));
  ZeroMemory(data, count);

  // Экспорт ключа шифрования
  if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, data, &count))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Key's export completed");

  std::ofstream fout;
  fout.open(public_key_file.toStdString().c_str(), std::ios_base::binary);
  if(fout.is_open())
  {
    fout.write((char*)data, count);
    ui->listWidget_2->addItem("Key exported to file");
    fout.close();
  }
  ui->listWidget_2->addItem(CMDEND);
}

void MainWindow::on_pushButton_5_clicked()
{
  HCRYPTKEY hNewKey;

  BYTE* data;
  DWORD count;
  DWORD err;

  std::ifstream fin;
  fin.open(public_key_file.toStdString().c_str(), std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count = fin.tellg();

    data = static_cast<BYTE*>(malloc(count));
    ZeroMemory(data, count);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)data, count);

    ui->listWidget_2->addItem("Key read from file");
    fin.close();

    if (!CryptAcquireContext(&hProv_asym_client, NULL, NULL,PROV_RSA_FULL, NULL))
    {
      err = GetLastError();
      ui->label_8->setText(QString::number(err));
      return;
    }
    ui->listWidget_2->addItem("Cryptographic provider initialized");

    if(!CryptImportKey(hProv_asym_client, data, count, 0, 0, &hNewKey))
    {
      err = GetLastError();
      ui->label_8->setText(QString::number(err));
      return;
    }
    hKey_public_client = hNewKey;
    ui->listWidget_2->addItem("Key's import completed");
  }
  ui->listWidget_2->addItem(CMDEND);
}

void MainWindow::on_pushButton_6_clicked()
{
  HCRYPTKEY hKey_session;

  DWORD count;
  DWORD err;

//CryptGenKey(hProv_asym_client, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT, &hKey_session)
  if (!CryptGenKey(hProv_asym_client, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &hKey_session))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Session key generated");

  std::wstring mess = ui->textEdit_3->toPlainText().toStdWString();
  count = mess.length()*2;

  if(!CryptEncrypt(hKey_session, 0, true, 0, (BYTE*)mess.c_str(), &count, mess.length()*2))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }

  ui->listWidget_2->addItem("Text Encrypted");
  ui->textEdit_4->setText(QString::fromStdWString(mess));

  std::ofstream fout;
  fout.open(message_file.toStdString().c_str(), std::ios_base::binary);
  if(fout.is_open())
  {
    fout.write((char*)mess.c_str(), count);
    ui->listWidget_2->addItem("Encrypted text written to file");
    fout.close();
  }

  /*
  // Получение ключа для экспорта ключа шифрования
  if (!CryptGetUserKey(hProv_asym_client, AT_KEYEXCHANGE, &hKey_public))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Public key is received");
  */

  count = 0;

  // Получение размера массива, используемого для экспорта ключа
  if (!CryptExportKey(hKey_session, hKey_public_client, SIMPLEBLOB, 0, NULL, &count))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }

  // Инициализация массива, используемого для экспорта ключа
  BYTE* data = static_cast<BYTE*>(malloc(count));
  ZeroMemory(data, count);

  // Экспорт ключа шифрования
  if (!CryptExportKey(hKey_session, hKey_public_client, SIMPLEBLOB, 0, data, &count))
  {
    err = GetLastError();
      ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Key's export completed");

  std::ofstream foutk;
  foutk.open(session_key_file.toStdString().c_str(), std::ios_base::binary);
  if(foutk.is_open())
  {
    foutk.write((char*)data, count);
    ui->listWidget_2->addItem("Key exported to file");
    foutk.close();
  }

  ui->listWidget_2->addItem(CMDEND);
}

void MainWindow::on_pushButton_7_clicked()
{
  HCRYPTPROV hProv_asym;
  HCRYPTKEY hKey_private;

  BYTE* data;
  DWORD count;
  DWORD count_mess;
  DWORD err;

  HCRYPTKEY hKey_session;

  if (!CryptAcquireContext(&hProv_asym, ui->lineEdit_2->text().toStdWString().c_str(), NULL, PROV_RSA_FULL, 0))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Cryptographic provider initialized");

  if (!CryptGetUserKey(hProv_asym, AT_KEYEXCHANGE, &hKey_private))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Private key is received");

  std::ifstream fin;
  fin.open(session_key_file.toStdString().c_str(), std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count = fin.tellg();
//    count = 140;

    data = static_cast<BYTE*>(malloc(count));
    ZeroMemory(data, count);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)data, count);

    ui->listWidget_2->addItem("Key read from file");
    fin.close();

    if(!CryptImportKey(hProv_asym, data, count, hKey_private, 0, &hKey_session))
    {
      err = GetLastError();
      ui->label_8->setText(QString::number(err));
      return;
    }

    ui->listWidget_2->addItem("Key's import completed");
  }

  fin.open(message_file.toStdString().c_str(), std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count = fin.tellg();
    count_mess = count;

    data = static_cast<BYTE*>(malloc(count + 2));
    ZeroMemory(data, count);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)data, count);

    ui->listWidget_2->addItem("Message read from file");
    fin.close();

    if(!CryptEncrypt(hKey_session, 0, true, 0, data, &count_mess, count))
    {
      err = GetLastError();
      ui->label_8->setText(QString::number(err));
      return;
    }

    *(data+count) = '\0';
    *(data+count+1) = '\0';
    std::wstring temp((wchar_t*)data);
//    temp.erase(count/2, temp.length());

    ui->listWidget_2->addItem(QString::fromStdString(std::string((char*)data)));
    ui->listWidget_2->addItem("Text Decrypted");
    ui->textEdit_4->setText(QString::fromStdWString(temp.c_str()));
  }

  ui->listWidget_2->addItem(CMDEND);
}


void MainWindow::on_pushButton_8_clicked()
{
  //QFileDialog file_dialog_pk;
  //file_dialog_pk.setAcceptMode(QFileDialog::AcceptSave);
  public_key_file = QFileDialog::getSaveFileName(this);//file_dialog_pk.getOpenFileName(this, "Публичный ключ", "");
}

void MainWindow::on_pushButton_9_clicked()
{
  //QFileDialog file_dialog_pk;
  //file_dialog_pk.setAcceptMode(QFileDialog::AcceptSave);
  session_key_file = QFileDialog::getSaveFileName(this);//file_dialog_pk.getOpenFileName(this, "Cессионый ключ", "");
}

void MainWindow::on_pushButton_10_clicked()
{
  //QFileDialog file_dialog_pk;
  //file_dialog_pk.setAcceptMode(QFileDialog::AcceptSave);
  message_file = QFileDialog::getSaveFileName(this);
}

//ЭП

void MainWindow::on_pushButton_11_clicked()
{
  HCRYPTKEY hKey_asym;

  DWORD err;

  // Получение контекста криптопровайдера
  if (!CryptAcquireContext(&hProv_sign_server, ui->lineEdit_3->text().toStdWString().c_str(), NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Cryptographic provider initialized");

  // Генерация ключа для тестирования
  if (!CryptGenKey(hProv_sign_server, AT_SIGNATURE, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &hKey_asym)) //!!! AT_SIGNATURE
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Private/Public keys generated");

  ui->listWidget_2->addItem(CMDEND);
}

void MainWindow::on_pushButton_12_clicked()
{
  DWORD err;
  HCRYPTHASH hHash;
  HCRYPTKEY hPublicKey;

  std::ofstream fout;

  // Cоздание хеш-объекта
  if(!CryptCreateHash(hProv_sign_server, CALG_MD5, 0, 0, &hHash))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Hash created");

  std::string mess = ui->textEdit_5->toPlainText().toStdString();
  DWORD count = mess.size();

  // Тестовые данные для хеширования
  //char string[] = "Test";
  //DWORD count = strlen(string);
  // Передача хешируемых данных хэш-объекту.

  if(!CryptHashData(hHash, (BYTE*)mess.c_str(), count, 0))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Hash data loaded");

  // Получение хеш-значения
  count = 0;
  if(!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &count, 0))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }

  char* hash_value = static_cast<char*>(malloc(count + 1));
  ZeroMemory(hash_value, count + 1);
  if(!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)hash_value, &count, 0))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Hash value is received");

  // Вывод на экран полученного хеш-значения
  ui->listWidget_2->addItem(QString::fromLocal8Bit(hash_value, (int)count));
  //std::cout << "Hash value: " << hash_value << std::endl;

  if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &count))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }

  char* sign_hash = static_cast<char*>(malloc(count + 1));
  ZeroMemory(sign_hash, count + 1);

  if(!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, (BYTE*)sign_hash, &count))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  DWORD sh_count = count;
  ui->listWidget_2->addItem("Signature created");

  // Вывод на экран значения цифровой подписи
  ui->listWidget_2->addItem(QString::fromLocal8Bit(sign_hash, (int)count));
  //std::cout << "Signature value: " << sign_hash << std::endl;

  fout.open(hash_file_sign.toStdString().c_str(), std::ios_base::binary);
  if(fout.is_open())
  {
    fout.write((char*)sign_hash, sh_count);
    ui->listWidget_2->addItem("Signature exported");
    fout.close();
  }

  fout.open(message_file_sign.toStdString().c_str(), std::ios_base::binary);
  if(fout.is_open())
  {
    fout.write((char*)mess.c_str(), mess.size());
    //fout.write("\0", 1);
    //fout.write("\0", 1);
    ui->listWidget_2->addItem("Message exported");
    fout.close();
  }

  // Получение ключа для экспорта ключа шифрования
  if (!CryptGetUserKey(hProv_sign_server, AT_SIGNATURE, &hPublicKey))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Public key is received");

  // Получение размера массива, используемого для экспорта ключа
  if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, NULL, &count))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }

  DWORD count_pk;
  count_pk = count;
  // Инициализация массива, используемого для экспорта ключа
  BYTE* data = static_cast<BYTE*>(malloc(count_pk));
  ZeroMemory(data, count_pk);

  // Экспорт ключа шифрования
  if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, data, &count_pk))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Key's export completed");

  fout.open(public_key_file_sign.toStdString().c_str(), std::ios_base::binary);
  if(fout.is_open())
  {
    fout.write((char*)data, count_pk);
    ui->listWidget_2->addItem("Public key exported");
    fout.close();
  }

  ui->listWidget_2->addItem(CMDEND);

  BOOL result = CryptVerifySignature(hHash, (BYTE*)sign_hash, sh_count, hPublicKey, NULL, 0);

  if (result == true)
  {
    ui->listWidget_2->addItem("+++");
  }
  else
  {
    ui->listWidget_2->addItem("---");
  }

  ui->listWidget_2->addItem(CMDEND);
}

void MainWindow::on_pushButton_13_clicked()
{
  HCRYPTKEY hNewKey;
  HCRYPTHASH hHash;

  BYTE* data;
  DWORD count;
  DWORD err;

  std::ifstream fin;

  BYTE* data_pk;
  DWORD count_pk;
  fin.open(public_key_file_sign.toStdString().c_str(), std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count_pk = fin.tellg();

    data_pk = static_cast<BYTE*>(malloc(count_pk));
    ZeroMemory(data_pk, count_pk);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)data_pk, count_pk);

    ui->listWidget_2->addItem("Key read from file");
    fin.close();

    if (!CryptAcquireContext(&hProv_sign_client, NULL, NULL,PROV_RSA_FULL, NULL))
    {
      err = GetLastError();
      ui->label_8->setText(QString::number(err));
      return;
    }
    ui->listWidget_2->addItem("Cryptographic provider initialized");

    if(!CryptImportKey(hProv_sign_client, data_pk, count_pk, 0, 0, &hNewKey))
    {
      err = GetLastError();
      ui->label_8->setText(QString::number(err));
      return;
    }
    hKey_public_client_sign = hNewKey;
    ui->listWidget_2->addItem("Key's import completed");
  }

  BYTE* data_mes;
  DWORD count_mess;
  fin.open(message_file_sign.toStdString().c_str(), std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count = fin.tellg();
    count_mess = count;

    data_mes = static_cast<BYTE*>(malloc(count));
    ZeroMemory(data_mes, count);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)data_mes, count);

    ui->listWidget_2->addItem("Message read from file");
    fin.close();

    //ui->textEdit_4->setText(QString::fromStdWString(temp.c_str()));
  }

  // Cоздание хеш-объекта
  if(!CryptCreateHash(hProv_sign_client, CALG_MD5, 0, 0, &hHash))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Hash created");

  //std::wstring mess = ui->textEdit_5->toPlainText().toStdWString();
  //DWORD count = mess.length()*2;

  // Тестовые данные для хеширования
  //char string[] = "Test";
  //DWORD count = strlen(string);
  // Передача хешируемых данных хэш-объекту.

  if(!CryptHashData(hHash, data_mes, count_mess, 0))
  {
    err = GetLastError();
    ui->label_8->setText(QString::number(err));
    return;
  }
  ui->listWidget_2->addItem("Hash data loaded");

  BYTE* data_sign;
  DWORD count_sign;
  fin.open(hash_file_sign.toStdString().c_str(), std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count = fin.tellg();
    count_sign = count;

    data_sign = static_cast<BYTE*>(malloc(count));
    ZeroMemory(data_sign, count);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)data_sign, count);

    ui->listWidget_2->addItem("Message read from file");
    fin.close();

    //ui->textEdit_4->setText(QString::fromStdWString(temp.c_str()));
  }

  BOOL result = CryptVerifySignature(hHash, data_sign, count_sign, hKey_public_client_sign, NULL, 0);

  if (result == true)
  {
    ui->listWidget_2->addItem("+++");
  }
  else
  {
    ui->listWidget_2->addItem("---");
  }

  ui->listWidget_2->addItem(CMDEND);
}

void MainWindow::on_pushButton_15_clicked()
{
  public_key_file_sign = QFileDialog::getSaveFileName(this);
}

void MainWindow::on_pushButton_14_clicked()
{
  message_file_sign = QFileDialog::getSaveFileName(this);
}

void MainWindow::on_pushButton_16_clicked()
{
  hash_file_sign = QFileDialog::getSaveFileName(this);
}
