package org.nmap4j.parsers;

import junit.framework.Assert;
import org.junit.Test;
import org.nmap4j.parser.INMapRunHandler;
import org.nmap4j.parser.NMapRunHandlerImpl;
import org.nmap4j.parser.NMapXmlHandler;
import org.nmap4j.parser.events.NMap4JParserEventListener;
import org.nmap4j.parser.events.ParserEvent;
import org.xml.sax.SAXException;
import test.constants.IConstants;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.io.InputStream;

public class NMapXmlHandlerTest implements IConstants {

	@Test
	public void basicTest() throws ParserConfigurationException, SAXException, IOException {


		INMapRunHandler nmrh = new NMapRunHandlerImpl();
		NMapXmlHandler nmxh = new NMapXmlHandler( nmrh );

		TestListener listener = new TestListener();

		nmxh.addListener( listener );

		SAXParserFactory spf = SAXParserFactory.newInstance();


		//get a new instance of parser
		SAXParser sp = spf.newSAXParser();

		// get the ms-vscan.xml as a stream
		try(InputStream in = getClass().getClassLoader().getResourceAsStream( NmapDataSamples.fileName )) {

			//parse the file and also register this class for call backs
			sp.parse( in, nmxh );
		}

		System.out.println( "\n\n exec time: " + nmxh.getExecTime() + "ms" );

	}


	private class TestListener implements NMap4JParserEventListener {


		@Override
		public void parseEventNotification(ParserEvent event) {
			//System.out.println( "source = " + event.getEventSource() ) ;
			if (event.getPayload() == null) {
				Assert.fail();
			}
		}

	}

}
