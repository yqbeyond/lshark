#ifndef MAINWINDOW_H
#define MAINWINDOW_H


//#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include <QtCore>
#include <QtGui>
#include <QtWidgets/QDirModel>
#include <QMessageBox>
#include <QMainWindow>
#include <QVector>
#include <QTime>
#include <QDebug>

#include "pkg_headers.h"

#define MAX_PKG_NUMS 1000 // max package nums
#define PKG_SIZE 2048 // pkg size

class MainWindow : public QMainWindow
{
	Q_OBJECT
	public:
        MainWindow(QWidget *parent = 0);
		QAction *actionStart;
		QAction *actionStop;
		QAction *actionClear;
		QAction *actionPort;
		QAction *actionIp_Address;
		QAction *actionMac_Address;
        QWidget *centralwidget;
		QGridLayout *gridLayout;
		QVBoxLayout *main_verticalLayout;
		QHBoxLayout *operateLayout;
		QPushButton *startButton;
		QPushButton *stopButton;
		QPushButton *clearButton;
		QHBoxLayout *select_horizontalLayout;
		QHBoxLayout *nic_horizontalLayout;
		QLabel *nic_label;
		QComboBox *nicBox;
		QHBoxLayout *ip_horizontalLayout;
		QLabel *ip_label;
		QLineEdit *ip_lineEdit;
		QHBoxLayout *port_horizontalLayout;
		QLabel *port_label;
		QLineEdit *port_lineEdit;
		QPushButton *applyButton;
        QTableWidget *pkgs_tableWidget;
		QTreeView *pkg_info_treeView;
		QTextBrowser *pkg_data_textBrowser;
		QMenuBar *menubar;
		QMenu *menuFile;
		QMenu *menuCapture;
		QMenu *menuOption;
        QStatusBar *statusbar;

        QTimer *timer;

        int index; // package index
        pcap_t* handle; // current pcap_t
        u_char PKG_BUFFER[MAX_PKG_NUMS][PKG_SIZE]; // package buffer
        bpf_u_int32 PKGS_SIZE[MAX_PKG_NUMS]; // each packet size
        u_char *buffer; // current package buffer
        QVector<QString> allNICs; // all NICs
        char curNIC[20]; // current NIC
        char filter_exp[100];                        //ilter expression [3]
        struct bpf_program fp;                   // compiled filter program (expression)
        bpf_u_int32 mask;                        // subnet mask
        bpf_u_int32 net;                         // ip
        bool status;  // running status

        void showTreeView(const u_char* packet); // show packet in tree view
        QString getProtocol(const u_char *packet); // get protocol
        QString getSrcIP(const u_char *packet); // get src Ip according to packet
        QString getDestIP(const u_char *packet); // get dest Ip according to packet
        //void get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
        QString get_package_line(const u_char *payload, int len, int offset); // get packets content in line
        QString get_package(const u_char *payload, int len); // return packet in "character" format

        // initial UI interface
        void setupUi(QMainWindow *MainWindow)
        {
            if (MainWindow->objectName().isEmpty())
                MainWindow->setObjectName(QStringLiteral("MainWindow"));
            MainWindow->resize(875, 571);
            actionStart = new QAction(MainWindow);
            actionStart->setObjectName(QStringLiteral("actionStart"));
            actionStop = new QAction(MainWindow);
            actionStop->setObjectName(QStringLiteral("actionStop"));
            actionClear = new QAction(MainWindow);
            actionClear->setObjectName(QStringLiteral("actionClear"));
            actionPort = new QAction(MainWindow);
            actionPort->setObjectName(QStringLiteral("actionPort"));
            actionIp_Address = new QAction(MainWindow);
            actionIp_Address->setObjectName(QStringLiteral("actionIp_Address"));
            actionMac_Address = new QAction(MainWindow);
            actionMac_Address->setObjectName(QStringLiteral("actionMac_Address"));

            centralwidget = new QWidget(MainWindow);
            centralwidget->setObjectName(QStringLiteral("centralwidget"));

            gridLayout = new QGridLayout(centralwidget);
            gridLayout->setObjectName(QStringLiteral("gridLayout"));
            main_verticalLayout = new QVBoxLayout();
            main_verticalLayout->setObjectName(QStringLiteral("main_verticalLayout"));
            operateLayout = new QHBoxLayout();
            operateLayout->setObjectName(QStringLiteral("operateLayout"));
            startButton = new QPushButton(centralwidget);
            startButton->setObjectName(QStringLiteral("startButton"));

            operateLayout->addWidget(startButton);
            stopButton = new QPushButton(centralwidget);
            stopButton->setObjectName(QStringLiteral("stopButton"));

            operateLayout->addWidget(stopButton);

            clearButton = new QPushButton(centralwidget);
            clearButton->setObjectName(QStringLiteral("clearButton"));

            operateLayout->addWidget(clearButton);


            main_verticalLayout->addLayout(operateLayout);

            select_horizontalLayout = new QHBoxLayout();
            select_horizontalLayout->setObjectName(QStringLiteral("select_horizontalLayout"));
            nic_horizontalLayout = new QHBoxLayout();
            nic_horizontalLayout->setObjectName(QStringLiteral("nic_horizontalLayout"));
            nic_label = new QLabel(centralwidget);
            nic_label->setObjectName(QStringLiteral("nic_label"));
            QFont font;
            font.setPointSize(10);
            font.setBold(false);
            font.setWeight(50);
            nic_label->setFont(font);
            nic_label->setScaledContents(false);
            nic_label->setWordWrap(false);

            nic_horizontalLayout->addWidget(nic_label);

            nicBox = new QComboBox(centralwidget);
            nicBox->setObjectName(QStringLiteral("nicBox"));

            nic_horizontalLayout->addWidget(nicBox);


            select_horizontalLayout->addLayout(nic_horizontalLayout);

            ip_horizontalLayout = new QHBoxLayout();
            ip_horizontalLayout->setObjectName(QStringLiteral("ip_horizontalLayout"));
            ip_label = new QLabel(centralwidget);
            ip_label->setObjectName(QStringLiteral("ip_label"));

            ip_horizontalLayout->addWidget(ip_label);

            ip_lineEdit = new QLineEdit(centralwidget);
            ip_lineEdit->setObjectName(QStringLiteral("ip_lineEdit"));

            ip_horizontalLayout->addWidget(ip_lineEdit);




			select_horizontalLayout->addLayout(ip_horizontalLayout);

			port_horizontalLayout = new QHBoxLayout();
			port_horizontalLayout->setObjectName(QStringLiteral("port_horizontalLayout"));
			port_label = new QLabel(centralwidget);
			port_label->setObjectName(QStringLiteral("port_label"));

			port_horizontalLayout->addWidget(port_label);

			port_lineEdit = new QLineEdit(centralwidget);
			port_lineEdit->setObjectName(QStringLiteral("port_lineEdit"));

			port_horizontalLayout->addWidget(port_lineEdit);


			select_horizontalLayout->addLayout(port_horizontalLayout);

			applyButton = new QPushButton(centralwidget);
			applyButton->setObjectName(QStringLiteral("applyButton"));

			select_horizontalLayout->addWidget(applyButton);


			main_verticalLayout->addLayout(select_horizontalLayout);

            pkgs_tableWidget = new QTableWidget(centralwidget);

            if (pkgs_tableWidget->columnCount() < 7)
                pkgs_tableWidget->setColumnCount(7);

			QStringList headers;
			headers << "No"<<"Time"<<"Source"<<"Destination"<<"Protocol"<<"Length"<<"Info";
            pkgs_tableWidget->setHorizontalHeaderLabels(headers);
			
            pkgs_tableWidget->setObjectName(QStringLiteral("pkgs_tableWidget"));
			QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
			sizePolicy.setHorizontalStretch(0);
			sizePolicy.setVerticalStretch(0);
            sizePolicy.setHeightForWidth(pkgs_tableWidget->sizePolicy().hasHeightForWidth());
            pkgs_tableWidget->setSizePolicy(sizePolicy);

            main_verticalLayout->addWidget(pkgs_tableWidget);

            pkg_info_treeView = new QTreeView(centralwidget);
			pkg_info_treeView->setObjectName(QStringLiteral("pkg_info_treeView"));

			main_verticalLayout->addWidget(pkg_info_treeView);

			pkg_data_textBrowser = new QTextBrowser(centralwidget);
			pkg_data_textBrowser->setObjectName(QStringLiteral("pkg_data_textBrowser"));

			main_verticalLayout->addWidget(pkg_data_textBrowser);

			gridLayout->addLayout(main_verticalLayout, 0, 0, 1, 1);

            MainWindow->setCentralWidget(centralwidget);
            menubar = new QMenuBar(MainWindow);
			menubar->setObjectName(QStringLiteral("menubar"));
			menubar->setGeometry(QRect(0, 0, 875, 26));
			menuFile = new QMenu(menubar);
			menuFile->setObjectName(QStringLiteral("menuFile"));
			menuCapture = new QMenu(menubar);
			menuCapture->setObjectName(QStringLiteral("menuCapture"));
			menuOption = new QMenu(menubar);
			menuOption->setObjectName(QStringLiteral("menuOption"));
            MainWindow->setMenuBar(menubar);
            statusbar = new QStatusBar(MainWindow);
			statusbar->setObjectName(QStringLiteral("statusbar"));
			statusbar->setSizeGripEnabled(true);
            MainWindow->setStatusBar(statusbar);

			menubar->addAction(menuFile->menuAction());
			menubar->addAction(menuCapture->menuAction());
			menubar->addAction(menuOption->menuAction());
			menuCapture->addAction(actionStart);
			menuCapture->addAction(actionStop);
			menuCapture->addAction(actionClear);
			menuOption->addAction(actionPort);
			menuOption->addAction(actionIp_Address);
			menuOption->addAction(actionMac_Address);

			setWindowTitle("Stupid Sinffer");
			actionStart->setText("Start");
			actionStop->setText("Stop");
			actionClear->setText("Clear");
			actionPort->setText("Port");
			actionIp_Address->setText("Ip Address");
			actionMac_Address->setText("Mac Address");
			startButton->setText("Start");
			stopButton->setText("Stop");
			clearButton->setText("Clear Package");
			nic_label->setText("NIC");
			nicBox->clear();
			nicBox->insertItems(0, QStringList()
					<< QApplication::translate("MainWindow", "none", 0)
					);
			ip_label->setText("IP Address");
			port_label->setText("Port");
			applyButton->setText("Apply");

			menuFile->setTitle("NIC");
			menuCapture->setTitle("Capture");
			menuOption->setTitle("Option");
            QMetaObject::connectSlotsByName(MainWindow);


        } // retranslateUi

        ~MainWindow()
        {
            if(!&this->fp)
            {
                pcap_freecode(&this->fp);
            }
            if (!&this->handle)
            {
                pcap_close(this->handle);
            }
        }
public slots:
        void onNICChanged(QString); // slot on current NIC changed
        void onApplyButtonClicked(); // apply filter when apply button clicked
        void onPkgItemSelect(int); // on package item select then parse it
        void start(); // start capture
        void stop(); // stop capture
        void clear(); // clear packages
};

#endif
