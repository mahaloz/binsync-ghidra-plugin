package binsync;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.SwingUpdateManager;

@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "BinSync",
	category = PluginCategoryNames.MISC,
	shortDescription = "BinSync Starter",
	description = "Collab",
	servicesRequired = { GoToService.class }
)
public class BinSyncPlugin extends ProgramPlugin implements DomainObjectListener {
	
	private DockingAction configBinSyncAction;
	
	public BinSyncPlugin(PluginTool tool, boolean consumeLocationChange, boolean consumeSelectionChange) {
		super(tool, consumeLocationChange, consumeSelectionChange);
		
		configBinSyncAction = new DockingAction("Configure BinSync...", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Msg.info(this, "Configuring BinSync Now...");
			}
		};
		
		configBinSyncAction.setEnabled(true);
		configBinSyncAction.setMenuBarData(new MenuData(new String[] { "Tools", "Configure BinSync" }));
		tool.addAction(configBinSyncAction);
	}
	
	@Override
	public void init() {
		super.init();
	}

	@Override
	public void dispose() {
		super.dispose();
	}
	
	/*
	 * Change Event Handler
	 */
	
	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_CODE_REMOVED)) {
			// reload or undo event has happend
			return;
		}
		

		// check for and handle commend added, comment deleted, and comment changed events
		if (ev.containsEvent(ChangeManager.DOCR_PRE_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_POST_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_EOL_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_PLATE_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED)) 
		{
			this.handleCmtChanged(ev);
		}
	}
	
	/*
	 * Comments
	 */
	
	private int getCommentType(int type) {
		if (type == ChangeManager.DOCR_PRE_COMMENT_CHANGED) {
			return CodeUnit.PRE_COMMENT;
		}
		if (type == ChangeManager.DOCR_POST_COMMENT_CHANGED) {
			return CodeUnit.POST_COMMENT;
		}
		if (type == ChangeManager.DOCR_EOL_COMMENT_CHANGED) {
			return CodeUnit.EOL_COMMENT;
		}
		if (type == ChangeManager.DOCR_PLATE_COMMENT_CHANGED) {
			return CodeUnit.PLATE_COMMENT;
		}
		if ((type == ChangeManager.DOCR_REPEATABLE_COMMENT_CHANGED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_ADDED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_REMOVED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_CREATED) ||
			(type == ChangeManager.DOCR_REPEATABLE_COMMENT_DELETED)) {
			return CodeUnit.REPEATABLE_COMMENT;
		}
		return -1;
	}
	
	private void handleCmtChanged(DomainObjectChangedEvent ev)
	{
		for (DomainObjectChangeRecord record : ev) {
			System.out.println("Comment changed called!");
			
			int type = record.getEventType();
			int commentType = getCommentType(type);
			if (commentType == -1) {
				continue;
			}

			ProgramChangeRecord pRec = (ProgramChangeRecord) record;

			String oldComment = (String) pRec.getOldValue();
			String newComment = (String) pRec.getNewValue();
			Address commentAddress = pRec.getStart();

			// if old comment is null then the change is an add comment so add the comment to the table
			if (oldComment == null) {
				//todo
				assert true;
			}

			// if the new comment is null then the change is a delete comment so remove the comment from the table
			else if (newComment == null) {
				//todo
				assert true;
			}
			// otherwise, the comment is changed so repaint the table
			else {
				//todo
				assert true;
			}
		}
		
	}

	
}
