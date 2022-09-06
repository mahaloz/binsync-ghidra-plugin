package binsync;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.server.*;
import org.apache.xmlrpc.webserver.WebServer;

import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.flatapi.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.services.DataTypeManagerService;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.database.function.LocalVariableDB;

import ghidra.util.data.DataTypeParser; 
import ghidra.util.data.DataTypeParser.AllowedDataTypes; 
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;

import binsync.BSGhidraServer;

public class BSGhidraServerAPI {
    private BSGhidraServer server;
	
	public BSGhidraServerAPI(BSGhidraServer server) {
		this.server = server;
	}
	
	/*
	 * Server Manipulation API 
	 */
	
	public Boolean ping() {
		return true;
	}
	
	public Boolean stop() {
		this.server.stop_server();
		return true;
	}
	
	public Boolean alertUIConfigured(Boolean config) {
		this.server.uiConfiguredCorrectly = config;
		return true;
	}
	
	/*
	 * Utils
	 */
	
	private Function getNearestFunction(Address addr) {
		if(addr == null)
			return null;
		
		var program = this.server.plugin.getCurrentProgram();
		var funcManager = program.getFunctionManager();
		var func =  funcManager.getFunctionContaining(addr);
		
		return func;
	}
	
	private Address strToAddr(String addrStr) {
		return this.server.plugin.getCurrentProgram().getAddressFactory().getAddress(addrStr);
	}
	
	private DecompileResults decompile(Function func) {
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.openProgram(this.server.plugin.getCurrentProgram());
		DecompileResults res = ifc.decompileFunction(func, 60, new ConsoleTaskMonitor());
		return res;
	}
	
	private LocalVariableDB getStackVariable(Function func, int offset) {
		for (Variable v : func.getAllVariables()) {
			if(v.getStackOffset() == offset) {
				return (LocalVariableDB) v;
			}
		}
		
		return null;
	}
	
	private DataType parseTypeString(String typeStr)
	{
		var dtService = this.server.plugin.getTool().getService(DataTypeManagerService.class);
		//var anan = AutoAnalysisManager.getAnalysisManager(this.server.plugin.getCurrentProgram()).getDataTypeManagerService();
		var dtParser = new DataTypeParser(dtService, AllowedDataTypes.ALL);
		
		DataType parsedType;
		try {
			parsedType = dtParser.parse(typeStr);
		} catch (Exception ex) {
			parsedType = null;
		}
		
		return parsedType;
	}
	
	/*
	 * 
	 * Decompiler API
	 *
	 */
	
	public String context() {
		return this.server.plugin.getProgramLocation().getAddress().toString();
	}
	
	/*
	 * Functions
	 * useful for function header parsing: https://github.com/extremecoders-re/ghidra-jni
	 */
	
	
	public Boolean setFunctionName(String addr, String name) {
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null)
			return false;
		
		
		var transID = program.startTransaction("update function name");
		try {
			func.setName(name, SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			System.out.println("Failed in setname: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return true;			
	}
	
	
	/*
	 * Comments
	 * useful: https://github.com/HackOvert/GhidraSnippets
	 */
	
	
	/*
	 * Stack Variables
	 */
	
	public Boolean setStackVarType(String addr, String offset, String typeStr) {
		var parsedType = parseTypeString(typeStr);
		if(parsedType == null)
			return false;
		
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null)
			return false;
		
		var v = getStackVariable(func, Integer.parseInt(offset));
		if(v == null)
			return false;
		
		
		var transID = program.startTransaction("update stackvar type");
		try {
			v.setDataType(parsedType, false, true, SourceType.ANALYSIS);
		} catch (Exception e) {
			System.out.println("Failed in stackvar settype: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return true;	
	}
	
	public Boolean setStackVarName(String addr, String offset, String name) {
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null)
			return false;
		
		var v = getStackVariable(func, Integer.parseInt(offset));
		if(v == null)
			return false;
		
		var transID = program.startTransaction("update stackvar name");
		try {
			v.setName(name, SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			System.out.println("Failed in stackvar setname: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		/*
		var decRes = this.decompile(func);
		if(decRes == null)
			return false;
		*/
		return true;
	}
	

	/*
	 * Global Vars
	 */
	
	/*
	 * Structs
	 */
	
	/*
	 * Enums
	 */
	
}
