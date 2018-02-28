/*
 * Copyright (c) 2010, nmap4j.org
 *
 * All rights reserved.
 *
 * This license covers only the Nmap4j library.  To use this library with
 * Nmap, you must also comply with Nmap's license.  Including Nmap within
 * commercial applications or appliances generally requires the purchase
 * of a commercial Nmap license (see http://nmap.org/book/man-legal.html).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the nmap4j.org nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
package org.nmap4j.parser;

import org.nmap4j.data.NMapRun;
import org.nmap4j.data.host.*;
import org.nmap4j.data.host.os.OsClass;
import org.nmap4j.data.host.os.OsMatch;
import org.nmap4j.data.host.os.PortUsed;
import org.nmap4j.data.host.ports.Port;
import org.nmap4j.data.host.scripts.HostScript;
import org.nmap4j.data.host.scripts.Script;
import org.nmap4j.data.host.trace.Hop;
import org.nmap4j.data.host.trace.Trace;
import org.nmap4j.data.nmaprun.*;
import org.nmap4j.data.nmaprun.host.ports.port.Service;
import org.nmap4j.data.nmaprun.host.ports.port.State;
import org.nmap4j.data.nmaprun.hostnames.Hostname;
import org.nmap4j.data.nmaprun.runstats.Finished;
import org.nmap4j.data.nmaprun.runstats.Hosts;
import org.nmap4j.parser.events.NMap4JParserEventListener;
import org.nmap4j.parser.events.ParserEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import java.lang.invoke.MethodHandles;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * This class is the implementation of the DefaultHandler and receives
 * notifications from the SAX parser when nodes are parsed.
 * <p>
 * From the NMap4J API standpoint, there should be little reason for you
 * to hook directly into this class (though you can if you want to).
 *
 * @author jsvede
 */
public class NMapXmlHandler extends DefaultHandler {
	final static Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

	private List<NMap4JParserEventListener> listeners;

	private final INMapRunHandler runHandler;

	private long parseStartTime = 0;

	private long parseEndTime = 0;

	// private member variables for creating the hierarchy
	private NMapRun nmapRun;
	private ScanInfo scanInfo;
	private Debugging debugging;
	private Verbose verbose;
	private Host host;
	private Status status;
	private Address address;
	private Hostnames hostnames;
	private Hostname hostname;
	private Ports ports;
	private Port port;
	private State state;
	private Service service;
	private Os os;
	private PortUsed portUsed;
	private OsClass osClass;
	private OsMatch osMatch;
	private Distance distance;
	private TcpSequence tcpSequence;
	private TcpTsSequence tcpTsSequence;
	private Times times;
	private Uptime uptime;
	private RunStats runStats;
	private Finished finished;
	private Hosts hosts;
	private Cpe cpe;
	private Trace trace;
	private Hop hop;
	private HostScript hostScript;
	private Script script;
	private String elemkey;

	private boolean isCpeData = false;

	private String previousQName;

	public NMapXmlHandler(INMapRunHandler handler) {
		listeners = new ArrayList<>();
		runHandler = handler;
	}

	private void fireEvent(Object payload) {
		if(payload==null){
			throw new InternalError("Nmap XML error, end tag with no beginning?");
		}
		ParserEvent event = new ParserEvent(this, payload);
		if (listeners != null && listeners.size() > 0) {
			Iterator<NMap4JParserEventListener> listenersIterator = listeners.iterator();
			while (listenersIterator.hasNext()) {
				NMap4JParserEventListener listener = listenersIterator.next();
				if (listener != null) {
					listener.parseEventNotification(event);
				}
			}
		}
	}

	public void addListener(NMap4JParserEventListener listener) {
		if (listeners == null) {
			listeners = new ArrayList<>();
		}
		listeners.add(listener);
	}

	public void removeListener(NMap4JParserEventListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void startDocument() throws SAXException {
		parseStartTime = System.currentTimeMillis();
	}

	private static String nestedTagErrorMsg(String tagName) {
		return String.format( "Error processing {} nmap XML tag inside {} tag. nested twice? his should not happen.", tagName , tagName );
	}

	@Override
	public void startElement(String uri, String localName, String qName,
							 Attributes attributes) throws SAXException {

		if (qName.equals(NMapRun.NMAPRUN_TAG)) {
			nmapRun = runHandler.createNMapRun(attributes);
		} else if (qName.equals(ScanInfo.SCANINFO_TAG)) {
			if(scanInfo!=null){
				throw new InternalError( nestedTagErrorMsg(qName) );
			}
			scanInfo = runHandler.createScanInfo(attributes);
			nmapRun.setScanInfo(scanInfo);
		} else if (qName.equals(Debugging.DEBUGGING_TAG)) {
			if(debugging!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			debugging = runHandler.createDebugging(attributes);
			nmapRun.setDebugging(debugging);
		} else if (qName.equals(Verbose.VERBOSE_TAG)) {
			if(verbose!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			verbose = runHandler.createVerbose(attributes);
			nmapRun.setVerbose(verbose);
		} else if (qName.equals(Host.HOST_TAG)) {
			if(host!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			host = runHandler.createHost(attributes);
			nmapRun.addHost(host);
		} else if (qName.equals(Status.STATUS_TAG)) {
			if(status!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			status = runHandler.createStatus(attributes);
			host.setStatus(status);
		} else if (qName.equals(Address.ADDRESS_TAG)) {
			if(address!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			address = runHandler.createAddress(attributes);
			host.addAddress(address);
		} else if (qName.equals(Hostnames.HOSTNAMES_TAG)) {
			if(hostnames!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			hostnames = runHandler.createHostnames(attributes);
			host.setHostnames(hostnames);
		} else if (qName.equals(Hostname.HOSTNAME_TAG)) {
			if(hostname!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			hostname = runHandler.createHostname(attributes);
			hostnames.setHostname(hostname);
		} else if (qName.equals(Ports.PORTS_TAG)) {
			if(ports!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			ports = runHandler.createPorts(attributes);
			host.setPorts(ports);
		} else if (qName.equals(Port.PORT_TAG)) {
			if(port!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			port = runHandler.createPort(attributes);
			ports.addPort(port);
		} else if (qName.equals(State.STATE_TAG)) {
			if(state!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			state = runHandler.createState(attributes);
			port.setState(state);
		} else if (qName.equals(Service.SERVICE_TAG)) {
			if(service!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			service = runHandler.createService(attributes);
			port.setService(service);
		} else if (qName.equals(Os.OS_TAG)) {
			if(os!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			os = runHandler.createOs(attributes);
			host.setOs(os);
		} else if (qName.equals(PortUsed.PORT_USED_TAG)) {
			if(portUsed!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			portUsed = runHandler.createPortUsed(attributes);
			os.addPortUsed(portUsed);
		} else if (qName.equals(OsClass.OSCLASS_TAG)) {
			if(osClass!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			osClass = runHandler.createOsClass(attributes);
			if(osMatch==null ){
				os.addOsClass( osClass );
			}else  {
				osMatch.addOsClass( osClass );
			}
		} else if (qName.equals(OsMatch.OS_MATCH_TAG)) {
			if(osMatch!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			osMatch = runHandler.createOsMatch(attributes);
			os.addOsMatch(osMatch);
		} else if (qName.equals(Distance.DISTANCE_TAG)) {
			if(distance!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			distance = runHandler.createDistance(attributes);
			host.setDistance(distance);
		} else if (qName.equals(TcpSequence.TCP_SEQUENCE_TAG)) {
			if(tcpSequence!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			tcpSequence = runHandler.createTcpSequence(attributes);
			host.setTcpSequence(tcpSequence);
		} else if (qName.equals(TcpTsSequence.TCP_TS_SEQUENCE_TAG)) {
			if(tcpTsSequence!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			tcpTsSequence = runHandler.createTcpTsSequence(attributes);
			host.setTcpTsSequence(tcpTsSequence);
		} else if (qName.equals(Times.TIMES_TAG)) {
			if(times!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			times = runHandler.createTimes(attributes);
			host.setTimes(times);
		} else if (qName.equals(Uptime.UPTIME_TAG)) {
			if(uptime!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			uptime = runHandler.createUptime(attributes);
			host.setUptime(uptime);
		} else if (qName.equals(RunStats.RUNSTATS_TAG)) {
			if(runStats!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			runStats = runHandler.createRunStats(attributes);
			nmapRun.setRunStats(runStats);
		} else if (qName.equals(Finished.FINISHED_TAG)) {
			if(finished!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			finished = runHandler.createFinished(attributes);
			runStats.setFinished(finished);
		} else if (qName.equals(Hosts.HOSTS_TAG)) {
			if(hosts!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			hosts = runHandler.createHosts(attributes);
			runStats.setHosts(hosts);
		} else if (qName.equals(Cpe.CPE_ATTR)) {
			isCpeData = true;
			cpe = runHandler.createCpe(attributes);
			if (previousQName.equals(OsClass.OSCLASS_TAG)) {
				osClass.addCpe(cpe);
			} else if (previousQName.equals(Service.SERVICE_TAG)) {

			}
		} else if (qName.equals(Trace.TRACE_TAG)) {
			if(trace!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			trace = runHandler.createTrace(attributes);
			host.setTrace(trace);
		} else if (qName.equals(Hop.HOP_TAG)) {
			if(hop!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			hop = runHandler.createHop(attributes);
			trace.addHop(hop);
		} else if (qName.equals(HostScript.TAG)) {
			if(hostScript!=null){
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			hostScript = runHandler.createHostScript(attributes);
			host.setHostScript(this.hostScript);
		} else if (qName.equals(Script.TAG)) {
			if (this.hostScript != null) {
				// There are mor tags named script that are not this case.
				this.script = runHandler.createScript(attributes);
				this.hostScript.addScript(this.script);
			} else if (this.port != null) {
				this.script = runHandler.createScript(attributes);
				this.port.addScript(this.script);
			}else{
				if("postscript".equals( previousQName) ){
					// TODO: This can happen but is not implemented yet.
				}else{
					throw new UnsupportedOperationException( "This is not supported because never happened in a wide range of tested data." );
				}
			}
		} else if (qName.equals(Script.ELEMTAG)) {
			if (this.elemkey != null) {
				throw new InternalError( nestedTagErrorMsg(qName));
			}
			// sometimes this.script == null in practice so I will not check it. Not sure if it should be.
			this.elemkey = attributes.getValue("key");
		}

		// set the previousQName for comparison to later elements
		previousQName = qName;
	}


	@Override
	public void characters(char[] ch, int start, int length)
			throws SAXException {
		if (isCpeData) {
			String cpeText = new String(ch, start, length);
			cpe.setCpeData(cpeText);
			isCpeData = false;
		}
		if (elemkey != null) {
			if (this.script != null) {
				String fragment = new String(ch, start, length);
				this.script.addElem(this.elemkey, fragment);
			}
		}
	}

	@Override
	public void endElement(String uri, String localName, String qName)
			throws SAXException {
		if (qName.equals(NMapRun.NMAPRUN_TAG)) {
			fireEvent(nmapRun);
			nmapRun = null;
		} else if (qName.equals(ScanInfo.SCANINFO_TAG)) {
			fireEvent(scanInfo);
			scanInfo = null;
		} else if (qName.equals(Debugging.DEBUGGING_TAG)) {
			fireEvent(debugging);
			debugging = null;
		} else if (qName.equals(Verbose.VERBOSE_TAG)) {
			fireEvent(verbose);
			verbose = null;
		} else if (qName.equals(Host.HOST_TAG)) {
			fireEvent(host);
			host = null;
		} else if (qName.equals(Status.STATUS_TAG)) {
			fireEvent(status);
			status = null;
		} else if (qName.equals(Address.ADDRESS_TAG)) {
			fireEvent(address);
			address = null;
		} else if (qName.equals(Hostname.HOSTNAME_TAG)) {
			fireEvent(hostname);
			hostname = null;
		} else if (qName.equals(Hostnames.HOSTNAMES_TAG)) {
			fireEvent(hostnames);
			hostnames = null;
		} else if (qName.equals(Ports.PORTS_TAG)) {
			fireEvent(ports);
			ports = null;
		} else if (qName.equals(Port.PORT_TAG)) {
			fireEvent(port);
			port = null;
		} else if (qName.equals(State.STATE_TAG)) {
			fireEvent(state);
			state = null;
		} else if (qName.equals(Service.SERVICE_TAG)) {
			fireEvent(service);
			service = null;
		} else if (qName.equals(Os.OS_TAG)) {
			fireEvent(os);
			os = null;
		} else if (qName.equals(PortUsed.PORT_USED_TAG)) {
			fireEvent(portUsed);
			portUsed = null;
		} else if (qName.equals(OsClass.OSCLASS_TAG)) {
			fireEvent(osClass);
			osClass = null;
		} else if (qName.equals(OsMatch.OS_MATCH_TAG)) {
			fireEvent(osMatch);
			osMatch = null;
		} else if (qName.equals(Distance.DISTANCE_TAG)) {
			fireEvent(distance);
			distance = null;
		} else if (qName.equals(TcpSequence.TCP_SEQUENCE_TAG)) {
			fireEvent(tcpSequence);
			tcpSequence = null;
		} else if (qName.equals(TcpTsSequence.TCP_TS_SEQUENCE_TAG)) {
			fireEvent(tcpTsSequence);
			tcpTsSequence = null;
		} else if (qName.equals(Times.TIMES_TAG)) {
			fireEvent(times);
			times = null;
		} else if (qName.equals(Uptime.UPTIME_TAG)) {
			fireEvent(uptime);
			uptime = null;
		} else if (qName.equals(RunStats.RUNSTATS_TAG)) {
			fireEvent(runStats);
			runStats = null;
		} else if (qName.equals(Finished.FINISHED_TAG)) {
			fireEvent(finished);
			finished = null;
		} else if (qName.equals(Hosts.HOSTS_TAG)) {
			fireEvent(hosts);
			hosts = null;
		} else if (qName.equals(Cpe.CPE_ATTR)) {
			fireEvent(cpe);
			cpe = null;
		} else if (qName.equals(Trace.TRACE_TAG)) {
			fireEvent(trace);
			trace = null;
		} else if (qName.equals(Hop.HOP_TAG)) {
			fireEvent(hop);
			hop = null;
		} else if (qName.equals(HostScript.TAG)) {
			fireEvent(hostScript);
			hostScript = null;
		} else if (qName.equals(Script.TAG)) {
			if (this.hostScript != null || this.port != null) {
				fireEvent(script);
				script = null;
			}
		} else if (qName.equals(Script.ELEMTAG)) {
			elemkey = null;
		}
	}

	@Override
	public void endDocument() throws SAXException {
		parseEndTime = System.currentTimeMillis();
	}

	public long getExecTime() {
		return parseEndTime - parseStartTime;
	}

}
