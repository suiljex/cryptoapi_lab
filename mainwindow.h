#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>

#include <windows.h>
#include <iostream>
#include <fstream>

#define CMDEND "-------"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

    void on_pushButton_3_clicked();

    void on_pushButton_4_clicked();

    void on_pushButton_5_clicked();

    void on_pushButton_6_clicked();

    void on_pushButton_7_clicked();

    void on_pushButton_8_clicked();

    void on_pushButton_9_clicked();

    void on_pushButton_10_clicked();

private:
    Ui::MainWindow *ui;

    HCRYPTPROV hProv_asym_server;
    HCRYPTPROV hProv_asym_client;
    HCRYPTKEY hKey_public_client;
    QString public_key_file;
    QString session_key_file;
    QString message_file;
};

#endif // MAINWINDOW_H
