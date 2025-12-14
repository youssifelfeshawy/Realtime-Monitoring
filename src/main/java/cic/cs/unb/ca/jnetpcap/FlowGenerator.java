package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;

import static cic.cs.unb.ca.jnetpcap.Utils.LINE_SEP;


public class FlowGenerator {
    public static final Logger logger = LoggerFactory.getLogger(FlowGenerator.class);

    //total 85 colums
	/*public static final String timeBasedHeader = "Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, "
			+ "Timestamp, Flow Duration, Total Fwd Packets, Total Backward Packets,"
			+ "Total Length of Fwd Packets, Total Length of Bwd Packets, "
			+ "Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,"
			+ "Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,"
			+ "Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,"
			+ "Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,"
			+ "Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,"
			+ "Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length,"
			+ "Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance,"
			+ "FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, "
			+ "CWR Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length,"
			+ "Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk,"
			+ "Bwd Avg Bulk Rate,"
			+ "Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes,"
			+ "Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,"
			+ "Active Mean, Active Std, Active Max, Active Min,"
			+ "Idle Mean, Idle Std, Idle Max, Idle Min, Label";*/

    //40/86
    private FlowGenListener mListener;
    private HashMap<String, BasicFlow> currentFlows;
    private HashMap<Integer, BasicFlow> finishedFlows;
    private HashMap<String, ArrayList> IPAddresses;

    // bidirectional is always assigned true in this application
    private boolean bidirectional;
    private long flowTimeOut;
    private long flowActivityTimeOut;
    private int finishedFlowCount;

    private static final List<ProtocolEnum> TCP_UDP_LIST_FILTER = Arrays.asList(ProtocolEnum.TCP, ProtocolEnum.UDP);

    public FlowGenerator(boolean bidirectional, long flowTimeout, long activityTimeout) {
        super();
        this.bidirectional = bidirectional;
        this.flowTimeOut = flowTimeout;
        this.flowActivityTimeOut = activityTimeout;
        init();
    }

    private void init() {
        currentFlows = new HashMap<>();
        finishedFlows = new HashMap<>();
        IPAddresses = new HashMap<>();
        finishedFlowCount = 0;
    }

    public void addFlowListener(FlowGenListener listener) {
        mListener = listener;
    }

    public void addPacket(BasicPacketInfo packet) {
        if (packet == null) {
            return;
        }

        BasicFlow flow;
        long currentTimestamp = packet.getTimeStamp();
        String id;

        if (this.currentFlows.containsKey(packet.fwdFlowId()) || this.currentFlows.containsKey(packet.bwdFlowId())) {

            if (this.currentFlows.containsKey(packet.fwdFlowId())) {
                id = packet.fwdFlowId();
            } else {
                id = packet.bwdFlowId();
            }

            flow = currentFlows.get(id); //The existing (original flow) that the packet is associated with

            // Flow finished due flowtimeout:
            // 1.- we move the flow to finished flow list
            // 2.- we eliminate the flow from the current flow list
            // 3.- we create a new flow with the packet-in-process
            if ((currentTimestamp - flow.getFlowStartTime()) > flowTimeOut ||
                    ((flow.getTcpFlowState() == TcpFlowState.READY_FOR_TERMINATION) && packet.hasFlagSYN())) {

                // set cumulative flow time if TCP packet
                if(TCP_UDP_LIST_FILTER.contains(flow.getProtocol())) {
                    long currDuration = flow.getCumulativeConnectionDuration();
                    currDuration += flow.getFlowDuration();
                    flow.setCumulativeConnectionDuration(currDuration);
                }

                if (mListener != null) {
                    mListener.onFlowGenerated(flow);
                } else {
                    finishedFlows.put(getFlowCount(), flow);
                    //flow.endActiveIdleTime(currentTimestamp,this.flowActivityTimeOut, this.flowTimeOut, false);
                }
                currentFlows.remove(id);  // Remove the expired flow from the current flow list

                // Create a new UDP flow if activity time difference between the current UDP packet, and the last
                // packet in the previous flow is greater than the flow activity timeout. This is to soften the issue
                // with hard separation UDP flows that are likely part of the same "dialogue", which can lead to single
                // packet flows with the hard flow time out cutoff. The concept of a "dialogue" is not well-defined in
                // UDP, like TCP, so we assume that if the activity time difference between the current packet and the
                // last packet in the previous flow is greater than the flow activity timeout, then the current packet
                // is part of a new "dialogue".
                boolean createNewUdpFlow =
                        (flow.getProtocol() == ProtocolEnum.UDP && currentTimestamp - flow.getLastSeen() > this.flowTimeOut);

                // If the original flow is set for termination, or the flow is not a tcp connection, create a new flow,
                // and place it into the currentFlows list
                // Having a SYN packet and no ACK packet means it's the first packet in a new flow
                if ((flow.getTcpFlowState() == TcpFlowState.READY_FOR_TERMINATION && packet.hasFlagSYN())      // tcp flow is ready for termination
                        || createNewUdpFlow                                                                    // udp packet is not part of current "dialogue"
                        || !TCP_UDP_LIST_FILTER.contains(packet.getProtocol())                                 // other protocols
                ) {
                    if(packet.hasFlagSYN() && packet.hasFlagACK()) {
                        // create new flow, switch direction - we assume the PCAP file had a mistake where SYN-ACK arrived before SYN packet
                        currentFlows.put(id, new BasicFlow(bidirectional,packet,packet.getDst(),packet.getSrc(),packet.getDstPort(),
                                packet.getSrcPort(), this.flowActivityTimeOut));
                    } else {
                        // Packet only has SYN, no ACK
                        currentFlows.put(id, new BasicFlow(bidirectional,packet,packet.getSrc(),packet.getDst(),packet.getSrcPort(),
                                packet.getDstPort(), this.flowActivityTimeOut));
                    }
                } else {
                  // Otherwise, the previous flow was likely terminated because of a timeout, and the new flow has to
                  // maintain the same source and destination information as the previous flow (since they're part of the
                  // same TCP connection or UDP "dialogue".
                    BasicFlow newFlow = new BasicFlow(bidirectional,packet,flow.getSrc(),flow.getDst(),flow.getSrcPort(),
                            flow.getDstPort(), this.flowActivityTimeOut, flow.getTcpPacketsSeen());

                    long currDuration = flow.getCumulativeConnectionDuration();
                    // get the gap between the last flow and the start of this flow
                    currDuration += (currentTimestamp - flow.getLastSeen());
                    newFlow.setCumulativeConnectionDuration(currDuration);
                    currentFlows.put(id, newFlow);
                }

                int cfsize = currentFlows.size();
                if (cfsize % 50 == 0) {
                    logger.debug("Timeout current has {} flow", cfsize);
                }

                // Flow finished due FIN flag (tcp only):
                // 1.- we add the packet-in-process to the flow (it is the last packet)
                // 2.- we move the flow to finished flow list
                // 3.- we eliminate the flow from the current flow list
            } else if (packet.hasFlagFIN()) {
                logger.debug("FlagFIN current has {} flow", currentFlows.size());
                flow.updateActiveIdleTime(currentTimestamp, this.flowActivityTimeOut);
                flow.addPacket(packet);

                // First FIN packet
                if (flow.getTcpFlowState() == null) {
                    flow.setTcpFlowState(TcpFlowState.FIRST_FIN_FLAG_RECEIVED);
                } else if (flow.getTcpFlowState() == TcpFlowState.FIRST_FIN_FLAG_RECEIVED) {

                    // Second FIN packet
                    if (flow.getFwdFINFlags() > 0 && flow.getBwdFINFlags() > 0) {
                        flow.setTcpFlowState(TcpFlowState.SECOND_FIN_FLAG_RECEIVED);
                    }
                }
                currentFlows.put(id, flow);
            } else if (packet.hasFlagRST()) {
                flow.updateActiveIdleTime(currentTimestamp, this.flowActivityTimeOut);
                flow.addPacket(packet);
                flow.setTcpFlowState(TcpFlowState.READY_FOR_TERMINATION);
                currentFlows.put(id, flow);
            } else if (packet.hasFlagACK()) {
                flow.updateActiveIdleTime(currentTimestamp, this.flowActivityTimeOut);
                flow.addPacket(packet);

                // Final ack packet for TCP flow termination
                if (flow.getTcpFlowState() == TcpFlowState.SECOND_FIN_FLAG_RECEIVED) {
                    flow.setTcpFlowState(TcpFlowState.READY_FOR_TERMINATION);
                }
                currentFlows.put(id, flow);
            } else if (flow.getProtocol() == ProtocolEnum.ICMP) {
                // create a new flow if the icmp code and types are different
                if (flow.getIcmpCode() != packet.getIcmpCode() &&
                        flow.getIcmpType() != packet.getIcmpType()) {
                    // finish existing flow
                    if (mListener != null) {
                        mListener.onFlowGenerated(flow);
                    } else {
                        finishedFlows.put(getFlowCount(), flow);
                    }
                    currentFlows.remove(id);

                    // create new flow
                    currentFlows.put(id, new BasicFlow(bidirectional,packet,packet.getSrc(),packet.getDst(),packet.getSrcPort(),
                            packet.getDstPort(), this.flowActivityTimeOut));

                } else {
                    // normal behavior
                    flow.updateActiveIdleTime(currentTimestamp, this.flowActivityTimeOut);
                    flow.addPacket(packet);
                    currentFlows.put(id, flow);
                }
            } else { // default
                flow.updateActiveIdleTime(currentTimestamp, this.flowActivityTimeOut);
                flow.addPacket(packet);
                currentFlows.put(id, flow);
            }
        } else { // not part of an existing flow

            if(packet.hasFlagSYN() && packet.hasFlagACK()){
                currentFlows.put(packet.bwdFlowId(), new BasicFlow(bidirectional,packet,packet.getDst(),packet.getSrc(),packet.getDstPort(),
                        packet.getSrcPort(), this.flowActivityTimeOut));
            }
            else {
                currentFlows.put(packet.fwdFlowId(), new BasicFlow(bidirectional, packet, this.flowActivityTimeOut));
            }
        }
    }

    /*public void dumpFlowBasedFeatures(String path, String filename,String header){
    	BasicFlow   flow;
    	try {
    		System.out.println("TOTAL Flows: "+(finishedFlows.size()+currentFlows.size()));
    		FileOutputStream output = new FileOutputStream(new File(path+filename));    
    		
    		output.write((header+"\n").getBytes());
    		Set<Integer> fkeys = finishedFlows.keySet();    		
			for(Integer key:fkeys){
	    		flow = finishedFlows.get(key);
	    		if(flow.packetCount()>1)				
	    			output.write((flow.dumpFlowBasedFeaturesEx()+"\n").getBytes());
			}
			Set<String> ckeys = currentFlows.keySet();   		
			for(String key:ckeys){
	    		flow = currentFlows.get(key);
	    		if(flow.packetCount()>1)				
	    			output.write((flow.dumpFlowBasedFeaturesEx()+"\n").getBytes());
			}			
			
			output.flush();
			output.close();			
		} catch (IOException e) {
			e.printStackTrace();
		}

    }*/

    public int dumpLabeledFlowBasedFeatures(String path, String filename, String header) {
        BasicFlow flow;
        int total = 0;
        int zeroPkt = 0;

        try {
            //total = finishedFlows.size()+currentFlows.size(); becasue there are 0 packet BasicFlow in the currentFlows

            FileOutputStream output = new FileOutputStream(new File(path + filename));
            logger.debug("dumpLabeledFlow: ", path + filename);
            output.write((header + "\n").getBytes());
            Set<Integer> fkeys = finishedFlows.keySet();
            for (Integer key : fkeys) {
                flow = finishedFlows.get(key);
                if (flow.packetCount() > 1) {
                    output.write((flow.dumpFlowBasedFeaturesEx() + "\n").getBytes());
                    total++;
                } else {
                    zeroPkt++;
                }
            }
            logger.debug("dumpLabeledFlow finishedFlows -> {},{}", zeroPkt, total);

            Set<String> ckeys = currentFlows.keySet();
            output.write((header + "\n").getBytes());
            for (String key : ckeys) {
                flow = currentFlows.get(key);
                if (flow.packetCount() >= 1) {
                    output.write((flow.dumpFlowBasedFeaturesEx() + "\n").getBytes());
                    total++;
                } else {
                    zeroPkt++;
                }

            }
            logger.debug("dumpLabeledFlow total(include current) -> {},{}", zeroPkt, total);
            output.flush();
            output.close();
        } catch (IOException e) {

            logger.debug(e.getMessage());
        }

        return total;
    }

    public long dumpLabeledCurrentFlow(String fileFullPath, String header) {
        if (fileFullPath == null || header == null) {
            String ex = String.format("fullFilePath=%s,filename=%s", fileFullPath);
            throw new IllegalArgumentException(ex);
        }

        File file = new File(fileFullPath);
        FileOutputStream output = null;
        int total = 0;
        try {
            if (file.exists()) {
                output = new FileOutputStream(file, true);
            } else {
                if (file.createNewFile()) {
                    output = new FileOutputStream(file);
                    output.write((header + LINE_SEP).getBytes());
                }
            }

            for (BasicFlow flow : currentFlows.values()) {
                if (flow.packetCount() >= 1) {

                    if (TCP_UDP_LIST_FILTER.contains(flow.getProtocol())) {
                        flow = updateTcpUdpCxnDuration(flow);
                    }

                    output.write((flow.dumpFlowBasedFeaturesEx() + LINE_SEP).getBytes());
                    total++;
                } else {

                }
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {
            try {
                if (output != null) {
                    output.flush();
                    output.close();
                }
            } catch (IOException e) {
                logger.debug(e.getMessage());
            }
        }
        return total;
    }


    private BasicFlow updateTcpUdpCxnDuration(BasicFlow tcpUdpFlow) {
        long currDuration = tcpUdpFlow.getCumulativeConnectionDuration();
        currDuration += tcpUdpFlow.getFlowDuration();
        tcpUdpFlow.setCumulativeConnectionDuration(currDuration);
        return tcpUdpFlow;
    }

    private int getFlowCount() {
        this.finishedFlowCount++;
        return this.finishedFlowCount;
    }

    public void clearCurrentFlows() {
        currentFlows.clear();
    }
}
