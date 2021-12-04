package projectreseau.networkanalyser.packet;

public interface IPProtocol {
    int IP = 0;
    int ICMP = 1;
    int TCP = 6;
    int UDP = 17;
    int IPV6 = 41;
    int MASK = 0xff;
    int INVALID = -1;
}
