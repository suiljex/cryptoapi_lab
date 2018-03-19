#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
  DWORD dwIndex=0;
  DWORD dwType;
  DWORD cbName;
  LPTSTR pszName;

  while (CryptEnumProviders(dwIndex, NULL, 0, &dwType, NULL, &cbName))
  {
    if (!cbName)
      break;
    if (!(pszName = (LPTSTR)LocalAlloc(LMEM_ZEROINIT, cbName)))
      return;
    if (!CryptEnumProviders(dwIndex++, NULL, 0, &dwType, pszName, &cbName))
    {
//      Error("CryptEnumProviders");
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

  // Получение контекста криптопровайдера
  if (!CryptAcquireContext(&hProv, NULL, NULL,PROV_RSA_FULL, NULL))
  {
//    Error("CryptAcquireContext");
    return;
  }
  ui->listWidget_2->addItem("Cryptographic provider initialized");

  // Cоздание хеш-объекта
  if(!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
  {
//    Error("CryptCreateHash");
    return;
  }
  ui->listWidget_2->addItem("Hash created");

  // Передача хешируемых данных хэш-объекту.

  std::string pass = ui->lineEdit->text().toStdString().c_str();
  DWORD count = pass.length();

  if(!CryptHashData(hHash, (BYTE*)(pass.c_str()), count, 0))
  {
//    Error("CryptHashData");
    return;
  }
  ui->listWidget_2->addItem("Hash data loaded");

  if(!CryptDeriveKey(hProv, CALG_RC4, hHash, NULL, &hKey))
  {
    return;
  }
  ui->listWidget_2->addItem("Key Derived");

  std::wstring mess = ui->textEdit->toPlainText().toStdWString();
  count = mess.length()*2;

  if(!CryptEncrypt(hKey, 0, true, 0, (BYTE*)mess.c_str(), &count, mess.length()*2))
  {
    return;
  }

  ui->listWidget_2->addItem("Text Encrypted");
  ui->textEdit_2->setText(QString::fromStdWString(mess));

  std::wofstream fout;
  fout.open("output.txt");
  if(fout.is_open())
  {
    fout << mess;
    ui->listWidget_2->addItem("File");
    fout.close();
  }

}

void MainWindow::on_pushButton_3_clicked()
{
  HCRYPTHASH hHash;

  // Получение контекста криптопровайдера
  if (!CryptAcquireContext(&hProv_asym, ui->lineEdit_2->text().toStdWString().c_str(), NULL,PROV_RSA_FULL, CRYPT_NEWKEYSET))
  {
//    Error("CryptAcquireContext");
    return;
  }

  ui->listWidget_2->addItem("Cryptographic provider initialized");

  // Генерация ключа для тестирования
  if (!CryptGenKey(hProv_asym, AT_KEYEXCHANGE, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &hKey_asym))
  {
    return;
  }
  ui->listWidget_2->addItem("Session key generated");

}

void MainWindow::on_pushButton_4_clicked()
{
  HCRYPTKEY hPublicKey;

  // Получение ключа для экспорта ключа шифрования
  if (!CryptGetUserKey(hProv_asym, AT_KEYEXCHANGE, &hPublicKey))
  {
    return;
  }

  ui->listWidget_2->addItem("Public key is received");

  DWORD count = 0;

  // Получение размера массива, используемого для экспорта ключа
  if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, NULL, &count))
  {
    return;
  }

  // Инициализация массива, используемого для экспорта ключа
  BYTE* data = static_cast<BYTE*>(malloc(count));
  ZeroMemory(data, count);

  // Экспорт ключа шифрования
  if (!CryptExportKey(hPublicKey, 0, PUBLICKEYBLOB, 0, data, &count))
  {
    return;
  }

  ui->listWidget_2->addItem("Key's export completed");

  std::ofstream fout;
  fout.open("output.txt");
  if(fout.is_open())
  {
    fout.write((char*)data, count);
    ui->listWidget_2->addItem("Key exported");
    fout.close();
  }
}

void MainWindow::on_pushButton_5_clicked()
{
  BYTE* data;
  DWORD count;

  std::ifstream fin;
  fin.open("output.txt", std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count = fin.tellg();

    data = static_cast<BYTE*>(malloc(count));
    ZeroMemory(data, count);

    fin.seekg(0, std::ios_base::beg);
    for (int br = 0; br < count; ++br)
    {
      fin.read((char*)data+br, 1);
    }
    ui->listWidget_2->addItem("Key read");
    fin.close();

    if (!CryptAcquireContext(&hProv_new, NULL, NULL,PROV_RSA_FULL, NULL))
    {
  //    Error("CryptAcquireContext");
      return;
    }

    if(!CryptImportKey(hProv_new, data, count, 0, 0, &hNewKey))
    {
      DWORD error = GetLastError();
      return;
    }
    ui->listWidget_2->addItem("Key's import completed");
  }
}

void MainWindow::on_pushButton_6_clicked()
{
  HCRYPTKEY hKey_local;
  HCRYPTKEY hKey_public;
  DWORD count;
  DWORD err;
/*
  if (!CryptAcquireContext(&hProv_local, NULL, NULL,PROV_RSA_FULL, NULL))
  {
//    Error("CryptAcquireContext");
    return;
  }
*/
  if (!CryptGenKey(hProv_new, CALG_RC4, CRYPT_EXPORTABLE | CRYPT_ENCRYPT | CRYPT_DECRYPT, &hKey_local))
  {
    return;
  }
  ui->listWidget_2->addItem("Session key generated");

  hKey_local_test = hKey_local;

  std::wstring mess = ui->textEdit_3->toPlainText().toStdWString();
  count = mess.length()*2;

  if(!CryptEncrypt(hKey_local, 0, true, 0, (BYTE*)mess.c_str(), &count, mess.length()*2))
  {
    return;
  }

  ui->listWidget_2->addItem("Text Encrypted");
  ui->textEdit_4->setText(QString::fromStdWString(mess));

  std::ofstream fout;
  fout.open("output_asym.txt");
  if(fout.is_open())
  {
    fout.write((char*)mess.c_str(), count);
    ui->listWidget_2->addItem("File");
    fout.close();
  }

/*
  // Получение ключа для экспорта ключа шифрования
  if (!CryptGetUserKey(hProv_new, AT_KEYEXCHANGE, &hKey_public))
  {
    err = GetLastError();
    return;
  }
  ui->listWidget_2->addItem("Public key is received");
*/

  count = 0;
  hKey_public = hNewKey;

  // Получение размера массива, используемого для экспорта ключа
  if (!CryptExportKey(hKey_local, hNewKey, SIMPLEBLOB, 0, NULL, &count))
  {
    err = GetLastError();
    return;
  }

  // Инициализация массива, используемого для экспорта ключа
  BYTE* data = static_cast<BYTE*>(malloc(count));
  ZeroMemory(data, count);

  // Экспорт ключа шифрования
  if (!CryptExportKey(hKey_local, hNewKey, SIMPLEBLOB, 0, data, &count))
  {
    err = GetLastError();
    return;
  }
  ui->listWidget_2->addItem("Key's export completed");

  std::ofstream foutk;
  foutk.open("output_enckey.txt");
  if(foutk.is_open())
  {
    foutk.write((char*)data, count);
    ui->listWidget_2->addItem("Key exported");
    foutk.close();
  }
}

void MainWindow::on_pushButton_7_clicked()
{
  BYTE* data;
  wchar_t* mess;
  DWORD count;
  DWORD count_mess;
  DWORD err;
  HCRYPTKEY hKey_private;
  HCRYPTKEY hKey_session;

  if (!CryptGetUserKey(hProv_asym, AT_KEYEXCHANGE, &hKey_private))
  {
    err = GetLastError();
    return;
  }
  ui->listWidget_2->addItem("Private key is received");

  std::ifstream fin;
  fin.open("output_enckey.txt", std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count = fin.tellg();
//    count = 140;

    data = static_cast<BYTE*>(malloc(count));
    ZeroMemory(data, count);

    fin.seekg(0, std::ios_base::beg);
    for (int br = 0; br < count; ++br)
    {
      fin.read((char*)data+br, 1);
    }
    ui->listWidget_2->addItem("Key read");
    fin.close();

    /*if(!CryptImportKey(hProv_asym, data, count, hKey_private, 0, &hKey_session))
    {
      err = GetLastError();
      return;
    }*/

    ui->listWidget_2->addItem("Key's import completed");
  }

  fin.open("output_asym.txt", std::ios_base::binary);
  if(fin.is_open())
  {
    fin.seekg(0, std::ios_base::end);
    count = fin.tellg();
    count_mess = count;

    data = static_cast<BYTE*>(malloc(count));
    ZeroMemory(data, count);

    fin.seekg(0, std::ios_base::beg);
    for (int br = 0; br < count; ++br)
    {
      fin.read((char*)data+br, 1);
    }
    ui->listWidget_2->addItem("Message read");
    fin.close();

    if(!CryptEncrypt(hKey_local_test, 0, true, 0, data, &count_mess, count))
    {
      err = GetLastError();
      return;
    }

    std::wstring temp((wchar_t*)data);
    temp.erase(count/2, temp.length());

    ui->listWidget_2->addItem("Text Decrypted");
    ui->textEdit_4->setText(QString::fromStdWString(temp.c_str()));
  }
}
