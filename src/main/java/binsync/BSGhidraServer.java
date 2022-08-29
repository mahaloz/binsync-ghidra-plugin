package binsync;

import org.apache.xmlrpc.server.*;
import org.apache.xmlrpc.webserver.WebServer;

class BSGhidraServerApi {
	public Integer sum(int x, int y){
		return x+y;
	}
}

public class BSGhidraServer {
    private static final int port = 8080;
	public Integer sum(int x, int y){
		return x+y;
	}

    public static void run() {
    try
    {
    	System.out.println("Attempting to start XML-RPC Server...");
        WebServer server = new WebServer(port);
        PropertyHandlerMapping phm = new PropertyHandlerMapping();
        phm.addHandler("bs", BSGhidraServer.class);
        server.getXmlRpcServer().setHandlerMapping(phm);
        server.start();
        
        System.out.println("Started successfully.");
        System.out.println("Accepting requests. (Halt program to stop.)");
     } catch (Exception exception){
          System.err.println("JavaServer: " + exception);
       }
    }
}
