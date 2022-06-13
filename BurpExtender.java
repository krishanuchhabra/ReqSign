package burp; //create a package burp

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

//create BurpExtender class and implement interface IBurpExtender

public class BurpExtender implements IBurpExtender, IHttpListener, ITab  {
	
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;     //creating an instance variable helpers of IExtensionHelpers type
	
	private PrintWriter debug;
	
	private JPanel panel;
	private String password = "DEFAULT";
	private JTextField passwordField;
	

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// TODO Auto-generated method stub
		
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
		this.callbacks.setExtensionName("MyCustomExtension");
		this.callbacks.registerHttpListener(this);    //registering the http listerner
		
		//no need to register the tab
		//invoke the tab
		
		SwingUtilities.invokeLater(new Runnable() {

			@Override
			public void run() {
				// TODO Auto-generated method stub
				
				panel = new JPanel();
				
				JLabel label =new JLabel("Password:");
				
				JButton button = new JButton("Submit1");
				
				passwordField = new JTextField();
				passwordField.setMaximumSize(new Dimension(300, passwordField.getPreferredSize().height));
				passwordField.setMinimumSize(new Dimension(300, passwordField.getPreferredSize().height));
				
				button.addActionListener(new ActionListener() {

					@Override
					public void actionPerformed(ActionEvent e) {
						
						password = passwordField.getText();
						
					}
					
				});
				
				
				GroupLayout layout = new GroupLayout(panel);
				panel.setLayout(layout);
				
				layout.setHorizontalGroup(layout.createSequentialGroup()
						.addGroup(layout.createParallelGroup()
								.addGroup(layout.createSequentialGroup()
										.addComponent(label)
										.addComponent(passwordField)
										)
								.addComponent(button, GroupLayout.Alignment.TRAILING)));
				
				layout.setVerticalGroup(layout.createSequentialGroup()
						.addGroup(layout.createParallelGroup()
								.addComponent(label)
								.addComponent(passwordField))
						
						.addComponent(button)
						);
				
				
				callbacks.customizeUiComponent(panel);
				callbacks.addSuiteTab(BurpExtender.this);
			}
			
		});
		
		this.debug = new PrintWriter(callbacks.getStdout(), true);  //the extensions stdout is Printwriter, true does an autoflush
		//this.debug.println("Hello");
		
		
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// TODO Auto-generated method stub
		
		if(messageIsRequest)
		{
			//this.debug.println("Intercepted Request");
			
			if(this.callbacks.TOOL_REPEATER == toolFlag)  //checks if the request is coming from the repeater 
			{
				//this.debug.println(messageInfo.getHost());
				
				IRequestInfo request = this.helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest());
				List<String> newHeaders = request.getHeaders();
				
				String path = messageInfo.getUrl().getPath();
				String query = messageInfo.getUrl().getQuery();
				String uri = "";
				
				if (query == null)
				{
					query= "";
					uri = path + password;
				}
				
				else
				{
					uri = path+ "?" + query + password; 
				}
				
				MessageDigest digest = null;
				try
				{
					digest = MessageDigest.getInstance("SHA-256");
				}
				catch(NoSuchAlgorithmException e) {
					e.printStackTrace();
				}
				
				byte[] encodedhash = digest.digest(uri.getBytes(StandardCharsets.UTF_8));
			
				String authToken = this.helpers.base64Encode(encodedhash);
				this.debug.println(new String(authToken));
				
				
				
				
				
				
				
				
				
				newHeaders.add("X-Custom-Header :" + authToken);                  //adding a new custom header
				
				int bodyOffset = request.getBodyOffset();
				String body = new String(messageInfo.getRequest()).substring(bodyOffset); 
				
				byte[] newRequest = this.helpers.buildHttpMessage(newHeaders, body.getBytes());
				messageInfo.setRequest(newRequest);
				
				
			}
		}
		
		
	}

	@Override
	public String getTabCaption() {
		// TODO Auto-generated method stub
		return "Test";
	}

	@Override
	public Component getUiComponent() {
		// TODO Auto-generated method stub
		return this.panel;
	}

}
