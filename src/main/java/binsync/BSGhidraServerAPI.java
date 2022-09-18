package binsync;

import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.server.*;
import org.apache.xmlrpc.webserver.WebServer;

import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
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
import ghidra.app.services.GoToService;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.database.function.LocalVariableDB;

import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.util.data.DataTypeParser; 
import ghidra.util.data.DataTypeParser.AllowedDataTypes; 
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.util.Msg;
import ghidra.app.script.GhidraScript;

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
		if(addr == null) {
			Msg.warn(this, "Failed to parse Addr string earlier, got null addr.");
			return null;
		}
		
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
	
	private FunctionDefinitionDataType parsePrototypeStr(String protoStr) 
	{
		// string must look something like:
		// 'void function1(int p1, int p2)' 
		var program = this.server.plugin.getCurrentProgram();
		var funcDefn = CParserUtils.parseSignature((ServiceProvider) null, program, protoStr);
		return funcDefn;
	}
	
	/*
	 * 
	 * Decompiler API
	 *
	 */
	
	public String context() {
		return this.server.plugin.getProgramLocation().getAddress().toString();
	}
	
	public String baseAddr() {
		return this.server.plugin.getCurrentProgram().getImageBase().toString();
	}
	
	public String binaryHash() {
		return this.server.plugin.getCurrentProgram().getExecutableMD5();
	}
	
	public String binaryPath() {
		return this.server.plugin.getCurrentProgram().getExecutablePath();
	}
	
	public Boolean gotoAddress(String addr) {
		GoToService goToService = this.server.plugin.getTool().getService(GoToService.class);
		goToService.goTo(this.strToAddr(addr));
		return true;
	}
	
	/*
	 * Functions
	 * useful for function header parsing: https://github.com/extremecoders-re/ghidra-jni
	 */
	
	
	public Boolean setFunctionName(String addr, String name) {
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}
		
		
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
	
	public Boolean setFunctionRetType(String addr, String typeStr) {
		var parsedType = parseTypeString(typeStr);
		if(parsedType == null) {
			Msg.warn(server, "Failed to parse type string!");;
			return false;
		}
		
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}
		
		
		var transID = program.startTransaction("update function ret type");
		try {
			func.setReturnType(parsedType, SourceType.ANALYSIS);
		} catch (Exception e) {
			Msg.warn(this, "Failed to do transaction on function settype: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return true;	
	}
	
	public Boolean setFunctionPrototype(String addr, String proto) {
		// Useful code refrences:
		// - https://github.com/NationalSecurityAgency/ghidra/blob/aa299897c6b84e16ecf228d82cf8957a9529b819/Ghidra/Features/Decompiler/src/main/java/ghidra/app/plugin/core/decompile/actions/OverridePrototypeAction.java#L271
		// - https://github.com/NationalSecurityAgency/ghidra/blob/aa299897c6b84e16ecf228d82cf8957a9529b819/Ghidra/Features/Decompiler/src/main/java/ghidra/app/plugin/core/decompile/actions/RetypeLocalAction.java
		//
		// It may actually be impossible to rename or retype just a single param and get propogation without moidifying the signature
		// directly... which sucks. The correct way to do this will be calling getFunctionPrototype(), replacing strings, and setting it back
		// TODO: finish this function!
		
		var parsedProto = parsePrototypeStr(proto);
		if(parsedProto == null) {
			Msg.warn(server, "Failed to parse prototype string!");;
			return false;
		}
		
		var program = this.server.plugin.getCurrentProgram();
		var parsedAddr = this.strToAddr(addr);
		var func = this.getNearestFunction(parsedAddr);
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}
		
		var transID = program.startTransaction("update function prototype");
		try {
			HighFunctionDBUtil.writeOverride(func, parsedAddr, parsedProto);
		} catch (Exception e) {
			Msg.warn(this, "Failed to do transaction on function settype: " + e.toString());
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
		if(parsedType == null) {
			Msg.warn(server, "Failed to parse type string!");;
			return false;
		}
		
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}
		
		var v = getStackVariable(func, Integer.decode(offset));
		if(v == null) {
			Msg.warn(server, "Failed to find a stack var by the offset " + offset);
			return false;
		}
		
		
		var transID = program.startTransaction("update stackvar type");
		try {
			v.setDataType(parsedType, false, true, SourceType.ANALYSIS);
		} catch (Exception e) {
			Msg.warn(this, "Failed to do transaction on stackvar settype: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
		return true;	
	}
	
	public Boolean setStackVarName(String addr, String offset, String name) {
		var program = this.server.plugin.getCurrentProgram();
		var func = this.getNearestFunction(this.strToAddr(addr));
		if(func == null) {
			Msg.warn(server, "Failed to find a function by the address " + addr);;
			return false;
		}
		
		var v = getStackVariable(func, Integer.decode(offset));
		if(v == null) {
			Msg.warn(server, "Failed to find a stack var by the offset " + offset);
			return false;
		}
		
		var transID = program.startTransaction("update stackvar name");
		try {
			v.setName(name, SourceType.ANALYSIS);
		} catch (DuplicateNameException | InvalidInputException e) {
			Msg.warn(this, "Failed in stackvar setname: " + e.toString());
			return false;
		} finally {
			program.endTransaction(transID, true);
		}
		
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
