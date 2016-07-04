#include <mainwindow.h>

MainWindow::MainWindow(QWidget *parent):QMainWindow(parent)
{    
    this->setupUi(this);
    this->timer = new QTimer(this);
    this->timer->setInterval(0);
    connect(timer, SIGNAL(timeout()), this, SLOT(start()));
    connect(applyButton, SIGNAL(clicked(bool)), this, SLOT(onApplyButtonClicked()));
    connect(pkgs_tableWidget, SIGNAL(cellClicked(int,int)), this, SLOT(onPkgItemSelect(int)));
    connect(startButton, SIGNAL(clicked(bool)), this, SLOT(start()));
    connect(stopButton, SIGNAL(clicked(bool)), this, SLOT(stop()));
    connect(clearButton, SIGNAL(clicked(bool)), this, SLOT(clear()));
    connect(nicBox, SIGNAL(currentIndexChanged(QString)), this, SLOT(onNICChanged(QString)));

    // check ip
    this->ip_lineEdit->setValidator(new QRegExpValidator(QRegExp("^((2[0-4]\\d|25[0-5]|[1-9]?\\d|1\\d{2})\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?):\\d{1,5}$")));
    // check port
    this->port_lineEdit->setValidator(new QRegExpValidator(QRegExp("^([0-9]|[1-9]\\d|[1-9]\\d{2}|[1-9]\\d{3}|[1-5]\\d{4}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5])$")));

    this->status = false;
    this->index = 0;
    this->pkgs_tableWidget->setRowCount(this->index);    

    char errbuf[PCAP_ERRBUF_SIZE];    
    // and nics
    pcap_if_t *nicards;
    pcap_if_t *dev;
    if (pcap_findalldevs(&nicards, errbuf) != -1){        
        for (dev = nicards; dev != NULL; dev=dev->next){
            this->allNICs.append(QString(dev->name));
            this->nicBox->addItem(QString(dev->name));
        }
    }

    // init default nic
    strcpy(this->curNIC, pcap_lookupdev(errbuf));
    if (pcap_lookupnet(this->curNIC, &this->net, &this->mask, errbuf) == -1) {
            fprintf(stderr, "Couldn't get netmask for device %s: %s\n",this->curNIC, errbuf);
            net = 0;
            mask = 0;
    }

    this->handle = pcap_open_live(this->curNIC, PKG_SIZE, 1, 0, errbuf); // 打开网络接口
    if (!this->handle)
    {
        qDebug()<<errbuf;        
    }
    else
    {
        this->status = true;
        this->timer->start();
        this->onApplyButtonClicked();
    }
}


// get protocol name according to packet
QString MainWindow::getProtocol(const u_char *packet)
{
    // to check if the package is a full header. eth(14) + ip(20) + tcp/udp(8)
    if (packet[12] == 0x08 && packet[13] == 0x06) // arp
    {
        return "ARP";
    }
    else if (packet[12] == 0x08 && packet[13] == 0x00) // ipv4
    {
        if (packet[14] >> 4 == 4) // ipv4 and ip head length(20 = 4 * 5)
        {
            if(packet[23] == 6) // tcp
            {
                if ((packet[34]<<8) + packet[35] == 80 || (packet[36]<<8)+packet[37] == 80)
                {
                    return "HTTP";
                }                
                else if ((packet[34]<<8) + packet[35] == 21 || (packet[36]<<8)+packet[37] == 21)
                {
                    return "FTP-Control";
                }
                else if ((packet[34]<<8) + packet[35] == 20 || (packet[36]<<8)+packet[37] == 20)
                {
                    return "FTP-Data";
                }
                else if ((packet[34]<<8) + packet[35] == 22 || (packet[36]<<8)+packet[37] == 22)
                {
                    return "SSH";
                }
                else if ((packet[34]<<8) + packet[35] == 53 || (packet[36]<<8)+packet[37] == 53)
                {
                    return "DNS";
                }
                else if ((packet[34]<<8) + packet[35] == 25 || (packet[36]<<8)+packet[37] == 25)
                {
                    return "SMTP";
                }
                else if ((packet[34]<<8) + packet[35] == 110 || (packet[36]<<8)+packet[37] == 110)
                {
                    return "POP3";
                }
                else if ((packet[34]<<8) + packet[35] == 443 || (packet[36]<<8)+packet[37] == 443)
                {
                    return "HTTPS";
                }
                else if ((packet[34]<<8) + packet[35] == 23 || (packet[36]<<8)+packet[37] == 23)
                {
                    return "TELNET";
                }
                else
                {
                    return "TCP";
                }
            }
            else if(packet[23] == 17) // udp
            {
                if ((packet[34]<<8) + packet[35] == 53 || (packet[36]<<8)+packet[37] == 53)
                {
                    return "DNS";
                }
                else
                {
                    return "UDP";
                }
            }
            else if (packet[23] == 1) // icmp
            {
                return "ICMP";
            }
            else if (packet[23] == 2) // igmp
            {
                return "IGMP";
            }
            else // other protocols
            {
                return "IPv4";
            }
        }
        else if (packet[14] >> 4 == 6)
        {
            if(packet[20] == 6) // tcp
            {
                if ((packet[54]<<8) + packet[55] == 80 || (packet[56]<<8)+packet[57] == 80)
                {
                    return "HTTP";
                }
                else if ((packet[54]<<8) + packet[55] == 21 || (packet[56]<<8)+packet[57] == 21)
                {
                    return "FTP-Control";
                }
                else if ((packet[54]<<8) + packet[55] == 20 || (packet[56]<<8)+packet[57] == 20)
                {
                    return "FTP-Data";
                }
                else if ((packet[54]<<8) + packet[55] == 22 || (packet[56]<<8)+packet[57] == 22)
                {
                    return "SSH";
                }
                else if ((packet[54]<<8) + packet[55] == 53 || (packet[56]<<8)+packet[57] == 53)
                {
                    return "DNS";
                }
                else if ((packet[54]<<8) + packet[55] == 25 || (packet[56]<<8)+packet[57] == 25)
                {
                    return "SMTP";
                }
                else if ((packet[54]<<8) + packet[55] == 110 || (packet[56]<<8)+packet[57] == 110)
                {
                    return "POP3";
                }
                else if ((packet[54]<<8) + packet[55] == 443 || (packet[56]<<8)+packet[57] == 443)
                {
                    return "HTTPS";
                }
                else if ((packet[54]<<8) + packet[55] == 23 || (packet[56]<<8)+packet[57] == 23)
                {
                    return "TELNET";
                }
                else
                {
                    return "TCP";
                }
            }
            else if(packet[20] == 17) // udp
            {
                if ((packet[54]<<8) + packet[55] == 53 || (packet[56]<<8)+packet[57] == 53)
                {
                    return "DNS";
                }
                else
                {
                    return "UDP";
                }
            }
            else if (packet[20] == 1) // icmp
            {
                return "ICMP";
            }
            else if (packet[20] == 2) // igmp
            {
                return "IGMP";
            }
            else // other protocols
            {
                return "IPv6";
            }
        }
    }
    else if (packet[12] == 0x80 && packet[13] == 0xdd) // ipv6
    {
        if(packet[20] == 6) // tcp
        {
            if ((packet[54]<<8) + packet[55] == 80 || (packet[56]<<8)+packet[57] == 80)
            {
                return "HTTP";
            }
            else if ((packet[54]<<8) + packet[55] == 21 || (packet[56]<<8)+packet[57] == 21)
            {
                return "FTP-Control";
            }
            else if ((packet[54]<<8) + packet[55] == 20 || (packet[56]<<8)+packet[57] == 20)
            {
                return "FTP-Data";
            }
            else if ((packet[54]<<8) + packet[55] == 22 || (packet[56]<<8)+packet[57] == 22)
            {
                return "SSH";
            }
            else if ((packet[54]<<8) + packet[55] == 53 || (packet[56]<<8)+packet[57] == 53)
            {
                return "DNS";
            }
            else if ((packet[54]<<8) + packet[55] == 25 || (packet[56]<<8)+packet[57] == 25)
            {
                return "SMTP";
            }
            else if ((packet[54]<<8) + packet[55] == 110 || (packet[56]<<8)+packet[57] == 110)
            {
                return "POP3";
            }
            else if ((packet[54]<<8) + packet[55] == 443 || (packet[56]<<8)+packet[57] == 443)
            {
                return "HTTPS";
            }
            else if ((packet[54]<<8) + packet[55] == 23 || (packet[56]<<8)+packet[57] == 23)
            {
                return "TELNET";
            }
            else
            {
                return "TCP";
            }
        }
        else if(packet[20] == 17) // udp
        {
            if ((packet[54]<<8) + packet[55] == 53 || (packet[56]<<8)+packet[57] == 53)
            {
                return "DNS";
            }
            else
            {
                return "UDP";
            }
        }
        else if (packet[20] == 1) // icmp
        {
            return "ICMP";
        }
        else if (packet[20] == 2) // igmp
        {
            return "IGMP";
        }
        else // other protocols
        {
            return "IPv6";
        }
    }
    return "Unparsed";
}

QString MainWindow::getSrcIP(const u_char *packet)
{    
    char srcIP[40];
    if (packet[12] == 0x08 && packet[13] == 0x00) // ip
    {        
        if (packet[14] >> 4 == 4)
        {
            sprintf(srcIP, "%d.%d.%d.%d", packet[26], packet[27], packet[28], packet[29]);
        }
        else if (packet[14] >> 4 == 6) // ipv6
        {
            sprintf(srcIP, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", packet[22], packet[23], packet[24], packet[25], packet[26], packet[27], packet[28], packet[29],packet[30], packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
        }
        return QString(srcIP);
    }
    else if (packet[12] == 0x08 && packet[13] == 0x06) // arp
    {     
        sprintf(srcIP, "%d.%d.%d.%d", packet[28], packet[29], packet[30], packet[31]);
        return QString(srcIP);
    }
    else if (packet[12] == 0x86 && packet[13] == 0xdd) //ipv6
    {     
        sprintf(srcIP, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", packet[22], packet[23], packet[24], packet[25], packet[26], packet[27], packet[28], packet[29],packet[30], packet[31], packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
        return QString(srcIP);
    }
    return "Unparsed";
}

QString MainWindow::getDestIP(const u_char *packet)
{
    char destIP[40];
    if (packet[12] == 0x08 && packet[13] == 0x00) // ip
    {
        if (packet[14] >> 4 == 4)
        {
            sprintf(destIP, "%d.%d.%d.%d", packet[30], packet[31], packet[32], packet[33]);
        }
        else if (packet[14] >> 4 == 6)
        {
            sprintf(destIP, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", packet[38], packet[39], packet[40], packet[41], packet[42], packet[43], packet[44], packet[45], packet[46], packet[47], packet[48], packet[49], packet[50], packet[51], packet[52], packet[53]);
        }
        return QString(destIP);
    }
    else if (packet[12] == 0x08 && packet[13] == 0x06) // arp
    {        
        sprintf(destIP, "%d.%d.%d.%d", packet[38], packet[39], packet[40], packet[41]);
        return QString(destIP);
    }
    else if (packet[12] == 0x86 && packet[13] == 0xdd) // ipv6
    {        
        sprintf(destIP, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", packet[38], packet[39], packet[40], packet[41], packet[42], packet[43], packet[44], packet[45], packet[46], packet[47], packet[48], packet[49], packet[50], packet[51], packet[52], packet[53]);
        return QString(destIP);
    }
    return "Unparsed";
}

/*
void MainWindow::get_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    this->pkgs_tableWidget->setRowCount(index+1);
    memcpy(PKG_BUFFER[index], (char*)packet, header->caplen); // add this packet to PKG BUFFER

    QTableWidgetItem *qtablewidgetitem_no = new QTableWidgetItem(QString::number(index, 10));
    QTableWidgetItem *qtablewidgetitem_time = new QTableWidgetItem(QTime::currentTime().toString("hh:mm:ss"));
    QTableWidgetItem *qtablewidgetitem_source = new QTableWidgetItem(this->getSrcIP(packet));
    QTableWidgetItem *qtablewidgetitem_destination = new QTableWidgetItem(this->getDestIP(packet));
    QTableWidgetItem *qtablewidgetitem_protocol = new QTableWidgetItem(this->getProtocol(packet));
    QTableWidgetItem *qtablewidgetitem_length = new QTableWidgetItem(QString::number(packet[16]<<8+packet[17] + 14, 10));
    QTableWidgetItem *qtablewidgetitem_info = new QTableWidgetItem(QString(""));

    this->pkgs_tableWidget->setItem(this->index, 0, qtablewidgetitem_no);
    this->pkgs_tableWidget->setItem(this->index, 1, qtablewidgetitem_time);
    this->pkgs_tableWidget->setItem(this->index, 2, qtablewidgetitem_source);
    this->pkgs_tableWidget->setItem(this->index, 3, qtablewidgetitem_destination);
    this->pkgs_tableWidget->setItem(this->index, 4, qtablewidgetitem_protocol);
    this->pkgs_tableWidget->setItem(this->index, 5, qtablewidgetitem_length);
    this->pkgs_tableWidget->setItem(this->index, 6, qtablewidgetitem_info);
    ++this->index;
}
*/
void MainWindow::start()
{    
    //set callback function (callback must be static or global)
    //  pcap_loop(this->handle, MAX_PKG_NUMS, this->get_packet, NULL);
    if (this->index >= MAX_PKG_NUMS - 1)
    {
        QMessageBox *msg = new QMessageBox(QMessageBox::Information, "Information","Capture At Most " + QString::number(MAX_PKG_NUMS, 10) + "packages.", QMessageBox::Yes, this);
        msg->exec();
        this->stop();
        return;
    }
    if (this->status == false || this->handle == NULL){
        char errbuf[PCAP_ERRBUF_SIZE];
        this->handle = pcap_open_live(this->curNIC, PKG_SIZE, 1, 0, errbuf); // 打开网络接口
        if (!this->handle)
        {
            printf("%s\n", errbuf);
            this->status = false;
            if (this->timer->isActive())
            {
                this->timer->stop();
            }
            qDebug()<<errbuf;
            return;
        }
        if (!this->timer->isActive()){
            this->timer->start();
        }
        this->status = true;
        this->onApplyButtonClicked(); // apply filter
    }

    struct pcap_pkthdr packet;
    printf("%d\n", this->index);
    const u_char* buf = pcap_next(this->handle, &packet);
    memcpy(this->PKG_BUFFER[this->index], buf, packet.caplen);

    this->PKGS_SIZE[this->index] = packet.caplen;
    if (!buf)
    {
        qDebug()<<"Did not capture a packet";
        return;
    }
    else
    {
        this->pkgs_tableWidget->setRowCount(this->index+1);
        QTableWidgetItem *qtablewidgetitem_no = new QTableWidgetItem(QString::number(this->index, 10));
        QTableWidgetItem *qtablewidgetitem_time = new QTableWidgetItem(QTime::currentTime().toString("hh:mm:ss"));
        QTableWidgetItem *qtablewidgetitem_source = new QTableWidgetItem(this->getSrcIP(buf));
        QTableWidgetItem *qtablewidgetitem_destination = new QTableWidgetItem(this->getDestIP(buf));
        QTableWidgetItem *qtablewidgetitem_protocol = new QTableWidgetItem(this->getProtocol(buf));
        QTableWidgetItem *qtablewidgetitem_length = new QTableWidgetItem(QString::number(packet.caplen, 10));
        QTableWidgetItem *qtablewidgetitem_info = new QTableWidgetItem(QString(""));

        this->pkgs_tableWidget->setItem(this->index, 0, qtablewidgetitem_no);
        this->pkgs_tableWidget->setItem(this->index, 1, qtablewidgetitem_time);
        this->pkgs_tableWidget->setItem(this->index, 2, qtablewidgetitem_source);
        this->pkgs_tableWidget->setItem(this->index, 3, qtablewidgetitem_destination);
        this->pkgs_tableWidget->setItem(this->index, 4, qtablewidgetitem_protocol);
        this->pkgs_tableWidget->setItem(this->index, 5, qtablewidgetitem_length);
        this->pkgs_tableWidget->setItem(this->index, 6, qtablewidgetitem_info);

        //this->pkg_data_textBrowser->setText(this->get_package(buf, packet.caplen));
        //this->showTreeView(buf);
        ++this->index;
    }
}

void MainWindow::stop()
{    
    if (this->status == true || !&this->handle )
    {        
        pcap_close(this->handle);
        this->handle = NULL;
        this->status = false;
    }
    if (this->timer->isActive()){
        this->timer->stop();
    }
}

void MainWindow::clear()
{
    this->pkgs_tableWidget->clearContents();
    this->pkgs_tableWidget->setRowCount(0);
    this->index = 0;
}

void MainWindow::onNICChanged(QString str)
{
    if (this->status == true)
    {
        this->stop();
        strcpy(this->curNIC, str.toLatin1().data());
        this->start();
    }
    else
    {
        strcpy(this->curNIC , str.toLatin1().data());

    }

}

void MainWindow::onApplyButtonClicked()
{
    if (!(this->ip_lineEdit->text().isEmpty()))
    {
        printf("%s",this->ip_lineEdit->text().toLatin1().data());
        strcpy(this->filter_exp, "net ");
        strcat(this->filter_exp, this->ip_lineEdit->text().toLatin1().data());
    }
    if (!(this->port_lineEdit->text().isEmpty()))
    {
        if (!(this->ip_lineEdit->text().isEmpty()))
        {
            strcat(this->filter_exp, " and port ");
        }
        else
        {
            strcpy(this->filter_exp, " and port ");
        }
        strcat(this->filter_exp, this->port_lineEdit->text().toLatin1().data());
    }
    //  compile the filter expression
    if (this->status == false || this->handle == NULL)
    {
        char errbuf[40];
        this->handle = pcap_open_live(this->curNIC, PKG_SIZE, 1, 0, errbuf); // 打开网络接口
        if (!this->handle)
        {
            qDebug()<<errbuf;
            return;
        }
    }

    if (pcap_compile(this->handle, &this->fp, this->filter_exp, 0, this->net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", this->filter_exp, pcap_geterr(this->handle));
    }
    //  apply the compiled filter
    if (pcap_setfilter(this->handle, &this->fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",this->filter_exp, pcap_geterr(this->handle));
    }
    return ;
}


void MainWindow::onPkgItemSelect(int row)
{    
    const char* buf = (char*)this->PKG_BUFFER[row];
    this->showTreeView((u_char*)buf);
    this->pkg_data_textBrowser->setText(this->get_package((u_char*)buf, this->PKGS_SIZE[row]));
}

void MainWindow::showTreeView(const u_char *packet)
{
    char buf[40];

    QStandardItemModel *model = new QStandardItemModel(5, 2);
    model->setHeaderData(0, Qt::Horizontal, "Protocol");
    model->setHeaderData(1, Qt::Horizontal, "Details");

    QStandardItem* item_eth = new QStandardItem("Ethernet");
    // ethernet
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);
    QStandardItem *eth_dest_mac = new QStandardItem("Destination MAC: " + QString(buf));
    sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
    QStandardItem *eth_src_mac = new QStandardItem("Source MAC: " + QString(buf));
    sprintf(buf, "%02x%02x", packet[12], packet[13]);
    QStandardItem *eth_type = new QStandardItem("Type : 0x" + QString(buf));
    item_eth->appendRow(eth_dest_mac);
    item_eth->appendRow(eth_src_mac);
    item_eth->appendRow(eth_type);
    model->setItem(0,0, item_eth);

    if (packet[12] == 0x08 && packet[13] == 0x00) // ip
    {

        QStandardItem* item_ip = new QStandardItem("IP");
        model->setItem(1,0, item_ip);
        QStandardItem *ip_version = new QStandardItem("Version " + QString::number(packet[14]>>4, 10));
        QStandardItem *ip_head_len = new QStandardItem("Head Length: " + QString::number(packet[14] & 0x0f, 10));
        QStandardItem *ip_tos = new QStandardItem("Type of Service: 0x" + QString::number(packet[15], 16));
        QStandardItem *ip_len = new QStandardItem("Total Length: " + QString::number((packet[16]<<8) + packet[17], 10));
        QStandardItem *ip_id = new QStandardItem("Identification: " + QString::number((packet[18]<<8) + packet[19], 10));
        QStandardItem *ip_flags = new QStandardItem("Flags: " + QString::number(packet[20]>>5, 10));
        QStandardItem *ip_off = new QStandardItem("Offset: " + QString::number(((packet[20] & 0x1f) << 8) + packet[21], 10));
        QStandardItem *ip_ttl = new QStandardItem("TTL: " + QString::number(packet[22], 10));
        QStandardItem *ip_protocol = new QStandardItem("Protocol: " + QString::number(packet[23], 10));
        QStandardItem *ip_chksum = new QStandardItem("Head Checck Sum: " + QString::number((packet[24]<<8) +packet[25], 10));
        sprintf(buf, "%d.%d.%d.%d", packet[26],packet[27],packet[28],packet[29]);
        QStandardItem *ip_src = new QStandardItem("Source IP: " + QString(buf));
        sprintf(buf, "%d.%d.%d.%d", packet[30],packet[31],packet[32],packet[33]);
        QStandardItem *ip_dest = new QStandardItem("Destination IP: " + QString(buf));
        item_ip->appendRow(ip_version);
        item_ip->appendRow(ip_head_len);
        item_ip->appendRow(ip_tos);
        item_ip->appendRow(ip_len);
        item_ip->appendRow(ip_id);
        item_ip->appendRow(ip_flags);
        item_ip->appendRow(ip_off);
        item_ip->appendRow(ip_ttl);
        item_ip->appendRow(ip_protocol);
        item_ip->appendRow(ip_chksum);
        item_ip->appendRow(ip_src);
        item_ip->appendRow(ip_dest);


        if (packet[23] == 6) // tcp
        {
            QStandardItem* item_tcp = new QStandardItem("TCP");
            model->setItem(2,0, item_tcp);

            QStandardItem *tcp_src_port = new QStandardItem("Source Port: " + QString::number((packet[34]<<8) + packet[35], 10));
            QStandardItem *tcp_dest_port = new QStandardItem("Destination Port: " + QString::number((packet[36]<<8) + packet[37], 10));
            QStandardItem *tcp_seq = new QStandardItem("Sequence Number: "+ QString::number((packet[38]<<24) + (packet[39]<<16) + (packet[40]<<8) + packet[41], 10));
            QStandardItem *tcp_ack = new QStandardItem("Acknowledge Number: " + QString::number((packet[42]<<24) + (packet[43]<<16) + (packet[44]<<8) + packet[45], 10));
            QStandardItem *tcp_head_len = new QStandardItem("Head Length: " + QString::number(packet[46]>>4, 10));
            QStandardItem *tcp_flags = new QStandardItem("Flags: " + QString::number(packet[47] & 0x3f, 10));
            QStandardItem *tcp_win = new QStandardItem("Window Size: " + QString::number((packet[48]<<8)+packet[49], 10));
            QStandardItem *tcp_chksum = new QStandardItem("Check Sum: " + QString::number((packet[50]<<8)+packet[51], 10));
            QStandardItem *tcp_urp = new QStandardItem("Urgent Pointer: " + QString::number((packet[52]<<8)+packet[53], 10));
            item_tcp->appendRow(tcp_src_port);
            item_tcp->appendRow(tcp_dest_port);
            item_tcp->appendRow(tcp_seq);
            item_tcp->appendRow(tcp_ack);
            item_tcp->appendRow(tcp_head_len);
            item_tcp->appendRow(tcp_flags);
            item_tcp->appendRow(tcp_win);
            item_tcp->appendRow(tcp_chksum);
            item_tcp->appendRow(tcp_urp);

            if ((packet[34]<<8) + packet[35] == 80 || (packet[36]<<8) + packet[37] == 80 )
            {
                QStandardItem* item_http = new QStandardItem("HTTP");                
                model->setItem(3, 0, item_http);               
            }
            else if ((packet[34]<<8) + packet[35] == 443 || (packet[36]<<8) + packet[37] == 443 )
            {
                QStandardItem* item_https = new QStandardItem("HTTPS");
                model->setItem(3, 0, item_https);
            }
            else if ((packet[34]<<8) + packet[35] == 53 || (packet[36]<<8) + packet[37] == 53 )
            {
                QStandardItem* item_dns = new QStandardItem("DNS");                
                model->setItem(3, 0, item_dns);                
            }
            else if ((packet[34]<<8) + packet[35] == 21 || (packet[36]<<8) + packet[37] == 21 || (packet[54]<<8) + packet[35] == 20 || (packet[56]<<8) + packet[57] == 20 )
            {
                QStandardItem* item_ftp = new QStandardItem("FTP");                                
                model->setItem(3, 0, item_ftp);              
            }
            QStandardItem* item_tcp_data = new QStandardItem();
            const u_char* data = packet + 54;
            item_tcp_data->setText(QString((char*)data));
            model->setItem(3, 1, item_tcp_data);
        }
        else if (packet[23] == 17) // udp
        {
            QStandardItem* item_udp = new QStandardItem("UDP");
            // udp
            QStandardItem *udp_src_port = new QStandardItem("Source Port: " + QString::number((packet[34]<<8)+packet[35], 10));
            QStandardItem *udp_dest_port = new QStandardItem("Destination Port: " + QString::number((packet[36]<<8)+packet[37], 10));
            QStandardItem *udp_len = new QStandardItem("Length: " + QString::number((packet[38]<<8)+packet[39], 10));
            QStandardItem *udp_chksum = new QStandardItem("Check Sum: " + QString::number((packet[40]<<8)+packet[41], 10));
            item_udp->appendRow(udp_src_port);
            item_udp->appendRow(udp_dest_port);
            item_udp->appendRow(udp_len);
            item_udp->appendRow(udp_chksum);
            if ((packet[34]<<8) + packet[35] == 53 || (packet[36]<<8) + packet[37] == 53 )
            {
                QStandardItem* item_dns = new QStandardItem("DNS");                
                model->setItem(3, 0, item_dns);                
            }
            QStandardItem* item_udp_data = new QStandardItem();
            const u_char* data = packet+54;
            item_udp_data->setText(QString((char*)data));
            model->setItem(3, 1, item_udp_data);
        }
        else if (packet[23] == 1) // icmp
        {
            QStandardItem* item_icmp = new QStandardItem("ICMP");
            QStandardItem* icmp_type = new QStandardItem("Type :" + QString::number(packet[34], 10));
            QStandardItem* icmp_code = new QStandardItem("Code: " + QString::number(packet[35], 10) );
            QStandardItem* icmp_chksum = new QStandardItem("Checck Sum " + QString::number((packet[36]<<8)+packet[37], 10));
            QStandardItem* icmp_data = new QStandardItem();          
            const u_char* data = packet+38;
            icmp_data->setText(QString((char*)data));
            item_icmp->appendRow(icmp_type);
            item_icmp->appendRow(icmp_code);
            item_icmp->appendRow(icmp_chksum);
            model->setItem(2, 0, item_icmp);
            model->setItem(2, 1, icmp_data);
        }
        else if (packet[23] == 2) // igmp
        {
            // igmp process code
        }

    }
    else if (packet[12] == 0x08 && packet[13] == 0x06) // arp
    {
        QStandardItem* item_arp = new QStandardItem("Arp");
        QStandardItem* arp_hrd = new QStandardItem("Hard Device Type: " + QString::number((packet[14]<<8)+packet[15],10));
        QStandardItem* arp_pro = new QStandardItem("Protocol Type: 0x" + QString::number((packet[16]<<8)+packet[17],16));
        QStandardItem* arp_hln = new QStandardItem("Hard Device Address Length: " + QString::number(packet[18], 10));
        QStandardItem* arp_pln = new QStandardItem("Protocol Length: " + QString::number(packet[19], 10));
        QStandardItem* arp_op = new QStandardItem("Operation Code: " + QString::number((packet[20]<<8)+packet[21], 10));
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", packet[22], packet[23], packet[24], packet[25], packet[26], packet[27]);
        QStandardItem* arp_src_mac = new QStandardItem("Sender Mac Address: " + QString(buf));
        sprintf(buf, "%d.%d.%d.%d", packet[28], packet[29], packet[30], packet[31]);
        QStandardItem* arp_src_ip = new QStandardItem("Sender Ip Adddress: " + QString(buf));
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", packet[32], packet[33], packet[34], packet[35], packet[36], packet[37]);
        QStandardItem* arp_dest_mac = new QStandardItem("Reciver Mac Address: " + QString(buf));
        sprintf(buf, "%d.%d.%d.%d", packet[38], packet[39], packet[40], packet[41]);
        QStandardItem* arp_dest_ip = new QStandardItem("Reciver Ip Address: " + QString(buf));
        model->setItem(1, 0, item_arp);
        item_arp->appendRow(arp_hrd);
        item_arp->appendRow(arp_pro);
        item_arp->appendRow(arp_hln);
        item_arp->appendRow(arp_pln);
        item_arp->appendRow(arp_op);
        item_arp->appendRow(arp_src_mac);
        item_arp->appendRow(arp_src_ip);
        item_arp->appendRow(arp_dest_mac);
        item_arp->appendRow(arp_dest_ip);
    }
    else
    {
        // Unparsed
    }

    this->pkg_info_treeView->setModel(model);
}


QString MainWindow::get_package_line(const u_char *payload, int len, int offset)
{
    QString line = "";
    int i;
    int gap;
    const u_char *ch;
    char buf[50];
    // offset
    sprintf(buf, "%05x   ", offset);
    line += QString(buf);

    // hex
    ch = payload;
    for(i = 0; i < len; i++) {
        sprintf(buf, "%02x ", *ch);
        line += QString(buf);
        ch++;
        // print extra space after 8th byte for visual aid
        if (i == 7)
        {
            line += " ";
        }
    }
    // print space to handle line less than 8 bytes
    if (len < 8)
        line += " ";
    // fill hex gap with spaces if not full line
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
             line += "   ";
        }
    }
    line += "   ";
    // ascii (if printable)
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            line += *ch;
        else
            line += ".";
        ch++;
    }
    line += "\n";
    return line;
}

// print visiable package

QString MainWindow::get_package(const u_char *payload, int len)
{
    QString lines = "";
    int len_rem = len; // length remain
    int line_width = 16; // number of per line
    int line_len;
    int offset = 0;  // zero-based offset counter
    const u_char *ch = payload;

    if (len <= 0)
        return lines;

    // data fits on one line
    if (len <= line_width) {
        lines += get_package_line(ch, len, offset);
        return lines;
    }
    // data spans multiple lines
    for ( ;; ) {
        // compute current line length
        line_len = line_width % len_rem;
        // print line
        lines += get_package_line(ch, line_len, offset);
        // compute total remaining
        len_rem = len_rem - line_len;
        // shift pointer to remaining bytes to print
        ch = ch + line_len;
        // add offset
        offset = offset + line_width;
        // check if we have line width chars or less
        if (len_rem <= line_width) {
            // print last line and get out
            lines += get_package_line(ch, len_rem, offset);
            break;
        }
    }

    return lines;
}

