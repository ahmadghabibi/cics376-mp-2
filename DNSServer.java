//******************************************************//
// usage: java UDPServer cics-376 mp-2  ahmad habibi
//******************************************************//

import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.io.*;

class DNSSrver
{
    public static boolean searchForMydomain(byte[] dnsQueryPacket, String myDomainName) throws IOException
    {
        ByteBuffer dnsByteBuffer = ByteBuffer.wrap(dnsQueryPacket); 
        dnsByteBuffer.position(12); // length of domain name is stored at this position
        StringBuilder domainName =  new StringBuilder();
        int len;
        boolean endDomain = false;
        boolean found = false;
        while(true)
        {    
            len = dnsByteBuffer.get() & 0xFF;   // get domain name len or len of label after domain name . move pointer forward
            if (len ==0 || found)
            {   
                break;   //End of domain name
            }
            byte[] label = new byte[len];
            dnsByteBuffer.get(label);
            if(domainName.length() > 0)
            {
                domainName.append(".");
                endDomain = true;
            }
            domainName.append(new String(label));
            if (endDomain)
            {
                 if (domainName.toString().matches(myDomainName))
                 {
                    found = true;
                 }
                domainName  = new StringBuilder();
                endDomain = false;
            }  
        }
        return found;
    }
    public static void prnDomainNames(byte[] dnsQueryPacket) throws IOException
    {
        ByteBuffer dnsByteBuffer = ByteBuffer.wrap(dnsQueryPacket); 
        dnsByteBuffer.position(12); // length of domain name is stored at this position
        StringBuilder domainName =  new StringBuilder();
        int len;
        boolean endDomain = false;
        while(true)
        {    
            len = dnsByteBuffer.get() & 0xFF;   // get domain name len or len of label after domain name . move pointer forward
            if (len ==0)
            {   
                break;   //End of domain name
            }
            byte[] label = new byte[len];
            dnsByteBuffer.get(label);
            if(domainName.length() > 0)
            {
                domainName.append(".");
                endDomain = true;
            }
            domainName.append(new String(label));
            if (endDomain)
            {
                System.out.println( domainName.toString());
                domainName  = new StringBuilder();
                endDomain = false;
            }  
        }
    }
    public static int extractTranId(byte[] dnsQuery)
    {
        ByteBuffer dnsBuffer = ByteBuffer.wrap(dnsQuery);
        int dnsQueryTranId  = dnsBuffer.getShort() & 0xFFFF;  
        return dnsQueryTranId;
    }

    public static void prnDNSHeader(DatagramPacket packet )
    {
        System.out.println("------------------ DNS Request Header------------------------------------------");
        System.out.println("Src port:" +  packet.getPort() + " Dest port: 53");
        byte[] query = packet.getData();
        // Header is 12 bytes
        System.out.printf("Trans Id: 0x%02X%02X\n ",query[0],query[1]);
        System.out.printf("Flags: 0x%02X%02X\n ",query[2],query[3]);
        System.out.printf("Questions: %d\n",(query[4] << 8 ) | query[5]);
        System.out.printf("Answer RRs: %d\n",(query[6] << 8 ) | query[7]);
        System.out.printf("Authority RRs: %d\n",(query[8] << 8 ) | query[9]);
        System.out.printf("Additional RRs: %d\n",(query[10] << 8 ) | query[11]);
    }
   
    public static void  printDNSPacket(DatagramPacket packet) throws IOException
    {
       prnDNSHeader(packet);
       prnDomainNames(packet.getData());
    }

    public static byte[] createResponse(DatagramPacket packet,  String myDomainName) throws IOException
    {
        ByteBuffer dnsResponseBuffer = ByteBuffer.allocate(512);
        int responseCode = 0 ;
        int    MyDomainIP[] = new int[4];
        int i = 0 ;
        byte[] domainIPBytes = InetAddress.getByName(myDomainName).getAddress();
        int transId = extractTranId(packet.getData());
        if (searchForMydomain(packet.getData(), myDomainName))
        {
            for (byte ipByte: domainIPBytes)
            {
                MyDomainIP[i++] = (ipByte & 0xFF);
            }
            responseCode = Integer.parseInt("8180", 16);  // no err 
        }
        else
        {
            MyDomainIP[0] = MyDomainIP[1] = MyDomainIP[2] = MyDomainIP[3] = (00 & 0xFF) ;
            responseCode = Integer.parseInt("8183", 16); // my domain not found
        }
       
       // Header section  12 bytes
       dnsResponseBuffer.putShort((short) transId); // TransId
       dnsResponseBuffer.putShort((short) responseCode); // Flags 
       dnsResponseBuffer.putShort((short) 1);      // num of questions = 1
       dnsResponseBuffer.putShort((short) 1);      // num of answer RRs = 1
       dnsResponseBuffer.putShort((short) 0);      // Authority RRs
       dnsResponseBuffer.putShort((short) 0);      // Additional RRs
        // Question section
        for (String part : myDomainName.split("\\."))
        {
            dnsResponseBuffer.put((byte) part.length());
            dnsResponseBuffer.put(part.getBytes());
        }
        dnsResponseBuffer.put((byte) 0); // End of domain name
        dnsResponseBuffer.putShort((short) 1); // Type A
        dnsResponseBuffer.putShort((short) 1); // Class IN
        // Answer section
        dnsResponseBuffer.putShort((short) 0xC00C); // Name (C=12, domain name  address)
        dnsResponseBuffer.putShort((short) 1);      // Type A
        dnsResponseBuffer.putShort((short) 1);      // Class IN
        dnsResponseBuffer.putInt(3600);       // TTL (1 hour)
        dnsResponseBuffer.putShort((short) 4);      // Data len
        byte[] payload = new byte[]{(byte) MyDomainIP[0], (byte) MyDomainIP[1], (byte) MyDomainIP[2], (byte) MyDomainIP[3]};
        dnsResponseBuffer.put(payload);
        return Arrays.copyOf(dnsResponseBuffer.array(), dnsResponseBuffer.position());
    }

    public static void main(String[] args) throws IOException
    {
    
       String myDomainName = "awesomesoftware.online";
       DatagramPacket rcvPacket;
       DatagramPacket udpSendPacket;
       byte[] dnsResponsePacket;
       DatagramSocket socket;
       socket = new DatagramSocket(53);
       rcvPacket = new DatagramPacket(new byte[65530],65530 );
       rcvPacket.setLength(65530); 
       udpSendPacket = new DatagramPacket(new byte[65530],65530 );
       udpSendPacket.setLength(65530); 
       System.out.println("Local DNS Server for --- awesomesoftware.online --- is up &  Running");

       while (true) 
       {
           socket.receive(rcvPacket);  
           InetAddress client_ip = rcvPacket.getAddress();
           int client_port = rcvPacket.getPort();
           dnsResponsePacket =  DNSSrver.createResponse(rcvPacket,myDomainName);
           udpSendPacket = new DatagramPacket(dnsResponsePacket,dnsResponsePacket.length, client_ip,client_port);        
           socket.send(udpSendPacket);      
           DNSSrver.printDNSPacket(rcvPacket) ;    
        }
    }
}
