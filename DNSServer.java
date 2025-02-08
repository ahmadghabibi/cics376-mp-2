//******************************************************//
// usage: java UDPServer port-number
//******************************************************//


import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.io.*;



class DNSSrver
{
    
    public static String extractDomainNames(byte[] dnsQueryPacket) throws IOException
    {

        ByteBuffer dnsByteBuffer = ByteBuffer.wrap(dnsQueryPacket); // create byte byfferArray
        dnsByteBuffer.position(12); // domain name starts here at position 12
        StringBuilder hostName = new StringBuilder();
        int len;
        while(true)
        {
            len = dnsByteBuffer.get() & 0xFF;
            if (len ==0)
            {
                break;
            }
            byte[] label = new byte[len];
            dnsByteBuffer.get(label);
            if(hostName.length() > 0)
            {
                hostName.append(".");
            }
            hostName.append(new String(label));
        }
        return hostName.toString();
    }
    public static int extractTranId(byte[] dnsQuery)
    {
        ByteBuffer dnsBuffer = ByteBuffer.wrap(dnsQuery);
        int dnsQueryTranId  = dnsBuffer.getShort() & 0xFFFF;
        return dnsQueryTranId;
    }

    public static byte[] createResponse(DatagramPacket packet,  String myDomainName,int queryResponseCode) throws IOException
    {

        ByteBuffer dnsResponseBuffer = ByteBuffer.allocate(512);
        
        byte[] domainIPBytes = InetAddress.getByName(myDomainName).getAddress();
        int    ipBytes[] = new int[4];
        int i = 0 ;
        for (byte ipByte: domainIPBytes)
        {
            ipBytes[i++] = (ipByte & 0xFF);
        }

        int transId = extractTranId(packet.getData());
        
       // Header section
       dnsResponseBuffer.putShort((short) transId); // TransId
       dnsResponseBuffer.putShort((short) queryResponseCode); // Flags (standard query response, no error)
       dnsResponseBuffer.putShort((short) 1);      // Questions
       dnsResponseBuffer.putShort((short) 1);      // Answer RRs
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
        dnsResponseBuffer.putShort((short) 0xC00C); // Name (C=12, position  domain name in question section)
        dnsResponseBuffer.putShort((short) 1);      // Type A
        dnsResponseBuffer.putShort((short) 1);      // Class IN
        dnsResponseBuffer.putInt(3600);       // TTL (1 hour)
        dnsResponseBuffer.putShort((short) 4);      // Data length
        dnsResponseBuffer.put(new byte[]{(byte) ipBytes[0], (byte) ipBytes[1], (byte) ipBytes[2], (byte) ipBytes[3]});
       return Arrays.copyOf(dnsResponseBuffer.array(), dnsResponseBuffer.position());
    }

    public static void prnDNSHeader(DatagramPacket packet )
    {
        byte[] query = packet.getData();
        InetAddress client_ip = packet.getAddress();
        int client_port = packet.getPort();
    
         System.out.println("User Datagram Protocol Src port 53, Dest port " +  client_port);

        // Header is 12 bytes
        System.out.println("Domain Name System query");
        System.out.printf("Trans Id: 0x%02X%02X\n ",query[0],query[1]);
        System.out.printf("Flags: 0x%02X%02X\n ",query[2],query[3]);
        System.out.printf("Questions: %d\n",(query[4] << 8 ) | query[5]);
        System.out.printf("Answer RRs: %d\n",(query[6] << 8 ) | query[7]);
        System.out.printf("Authority RRs: %d\n",(query[8] << 8 ) | query[9]);
        System.out.printf("Additional RRs: %d\n",(query[10] << 8 ) | query[11]);
    }
 
    public static int printDNSName(byte bytes[], int start)
    {
       
        int pos = start;
        while (bytes[pos] != 0)
         {
            if (pos != start) 
            {
                System.out.print(".");
            } 
            int length = bytes[pos];
            // POINTER!  We recursively print from a different place in the packet
            if (length == -64) {
                int pos2 = bytes[pos+1] & 0xFF;
                printDNSName(bytes, pos2);
                pos++;
                break;
    
            // Otherwise the "length" is the number of characters in this part of
            // name.
            } else {
                for (int i=1; i<=length; i++) {
                    System.out.print((char)bytes[pos+i]);
                }
                pos += length+1;
            }
        }
        pos ++;
        System.out.println("");
        return pos;
    }
    public static void  printDNSPacket(DatagramPacket packet) 
    {
       int domainNameStartPos = 12 ;
       printDNSName(packet.getData(),domainNameStartPos);
       prnDNSHeader(packet);
    }


    public static void main(String[] args) throws IOException
    {
    
       String myDomainName = "awesomesoftware.online";
       DatagramPacket packet;
       DatagramSocket socket;
       socket = new DatagramSocket(53);
       packet = new DatagramPacket(new byte[65530],65530 );
       packet.setLength(65530); 
       System.out.println("Local DNS Server is listeing on port 53");
       byte[] dnsResponse = null;
       String domainNames ;
       while (true) 
       {
           socket.receive(packet);  
           printDNSPacket(packet) ;
           InetAddress client_ip = packet.getAddress();
           int client_port = packet.getPort();
           domainNames = extractDomainNames(packet.getData());  
           if (domainNames.matches(myDomainName))
           {
                dnsResponse =  DNSSrver.createResponse(packet,myDomainName,Integer.parseInt("8180", 16)); // no error
           }
           else
           {
                dnsResponse =  DNSSrver.createResponse(packet,myDomainName,Integer.parseInt("8183", 16)); // error
           }
           packet = new DatagramPacket(dnsResponse,dnsResponse.length, client_ip,client_port);        
           socket.send(packet);          
        }
    }
}




