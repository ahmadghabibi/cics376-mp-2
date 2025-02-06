//******************************************************//
// usage: java UDPServer port-number
//******************************************************//


import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.io.*;

class DNSSrver
{
    public static void prnName(DatagramPacket packet)
    {
        byte bytes[] = packet.getData();
        for (int i =0;i<packet.getLength();i++)
        {
            System.out.print((char)bytes[i]);
        }
        System.out.println("");
        System.out.println("-----------------------------------");
    }
    public static int printDNSName(byte bytes[], int start)
    {
       
        int pos = start;
        while (bytes[pos] != 0) {
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
        return pos;
    }
    public static void  printDNSPacket(DatagramPacket packet) 
    {
       
       int pos =  printDNSName(packet.getData(),packet.getLength());
       System.out.println(pos);
      
       // System.out.println("*** packet received from " + packet.getAddress().getHostAddress());
        //System.out.println("*** packet received from " + packet.getData());
    }
    public static int extractTranId(byte[] dnsQuery)
    {

        ByteBuffer dnsBuffer = ByteBuffer.wrap(dnsQuery);
        int dnsQueryTranId  = dnsBuffer.getShort() & 0xFFFF;
        return dnsQueryTranId;
    }
    public static byte[] createDNSRes(DatagramPacket packet,   String domainName) throws IOException
    {

        ByteBuffer dnsResponseBuffer = ByteBuffer.allocate(512);
        
        byte[] domainIPBytes = InetAddress.getByName(domainName).getAddress();
        int    ipBytes[] = new int[4];
        int i = 0 ;
        for (byte ipByte: domainIPBytes)
        {
            ipBytes[i++] = (ipByte & 0xFF);
        }

        int transId = extractTranId(packet.getData());
        
       // Header section
       dnsResponseBuffer.putShort((short) transId); // TransId
       dnsResponseBuffer.putShort((short) 0x8180); // Flags (standard query response, no error)
       dnsResponseBuffer.putShort((short) 1);      // Questions
       dnsResponseBuffer.putShort((short) 1);      // Answer RRs
       dnsResponseBuffer.putShort((short) 0);      // Authority RRs
       dnsResponseBuffer.putShort((short) 0);      // Additional RRs
        // Question section
        for (String part : domainName.split("\\."))
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

    public static String extractHostName(byte[] dnsQueryPacket) throws IOException
    {

        ByteBuffer dnsByteBuffer = ByteBuffer.wrap(dnsQueryPacket);
        dnsByteBuffer.position(12); // domain name starts here
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
    public static void main(String[] args) throws IOException
    {
    
       String domainName = "awesomesoftware.online";
       DatagramPacket packet;
       DatagramSocket socket;
       socket = new DatagramSocket(53);
       packet = new DatagramPacket(new byte[65530],65530 );
       packet.setLength(65530); 
       System.out.println("Local DNS Server is listeing on port 53");
       
       while (true) 
       {
        
           socket.receive(packet);  
           InetAddress client_ip = packet.getAddress();
           int client_port = packet.getPort();

           String hostNames = extractHostName(packet.getData());
           System.out.println("DNS Hosts: " + hostNames);
           byte[] dnsResponse = null;
           if (hostNames.indexOf("awesomesoftware.online") > 0)
           {
               //byte[] dnsResponse =  DNSSrver.createDNSRes(packet,domainName);
                dnsResponse =  DNSSrver.createDNSRes(packet,domainName);
           }
           else
           {
                dnsResponse =  DNSSrver.createDNSRes(packet,domainName);
           }
           
          
           packet = new DatagramPacket(dnsResponse,dnsResponse.length, client_ip,client_port);        
           socket.send(packet);
          // prnName(packet);
         }
    }
}




