# Network Analyser
Ce programme est un mini analyseur de protocole réseau. Il prend en entrée un ﬁchier trace contenant les octets capturés préalablement sur un réseau Ethernet.

Cet analyseur comprend actuellement les protocoles suivants :

- Couche 2: Ethernet
- Couche 3: IP
- Couche 4: UDP
- Couche 7: DNS et DHCP
                                    

![iShot2021-12-04 16.58.47](https://raw.githubusercontent.com/zhenyuefu/picbed/master/202112041659510.png)



Cliquez sur `Open` dans la menu `File` , ou appuyez sur le `cmd+o` pour ouvir un ﬁchier trace.

Cliquez sur le `export` dans la menu `File` , toutes les informations peuvent être exportées au format `Plain Text`

## How To Run

### Download Portable

> The latest releases are available from the [Github releases page](https://github.com/zhenyuefu/NetworkAnalyser/releases).

L'application peut être décompressée et exécutée directement.

Si vous utilisez macOS, la commande suivante doit être exécutée dans le terminal pour autoriser les applications non signées.

`sudo spctl --master-disable`



### Run from source code

#### Dev Dependence

- jdk 17
- maven

#### Run 

Dans le répertoire du projet, il suffit d'exécuter la commande suivante pour lancer le programme : 

`mvn clean javafx:run`



## File Structure

```bash
.
├── 1.txt       # example input file
├── 2.txt       # example input file
├── README.md
├── export.txt  # example output file
├── package.sh
├── pom.xml     # maven config
└── src
    └── main
        ├── java
        │   ├── module-info.java
        │   └── projectreseau
        │       └── networkanalyser
        │           ├── Launcher.java
        │           ├── MainApplication.java
        │           ├── MainController.java         # UI Controler
        │           ├── packet
        │           │   ├── ContentFrame.java
        │           │   ├── DHCPPacket.java
        │           │   ├── DNSPacket.java
        │           │   ├── EthernetPacket.java
        │           │   ├── EthernetProtocol.java
        │           │   ├── Frame.java
        │           │   ├── FrameAnalyser.java       # Alalyse the packet and show on gui
        │           │   ├── IPAddress.java
        │           │   ├── IPPacket.java
        │           │   ├── IPProtocol.java
        │           │   ├── MACAddress.java
        │           │   ├── Packet.java
        │           │   ├── PacketAnalyser.java      # handle input file to packets
        │           │   └── UDPPacket.java
        │           ├── test
        │           │   └── TestParser.java
        │           └── util
        │               ├── ArrayHelper.java
        │               ├── FileUtility.java
        │               ├── HexUtils.java
        │               └── TimeUtils.java
        └── resources
            └── projectreseau
                └── networkanalyser
                    └── net.fxml

```



## Collaborator

<a href = "https://github.com/Tanu-N-Prabhu/Python/graphs/contributors">
  <img src = "https://contrib.rocks/image?repo=zhenyuefu/NetworkAnalyser" alt=""/>
</a>

