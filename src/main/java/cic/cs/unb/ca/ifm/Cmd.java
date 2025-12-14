package cic.cs.unb.ca.ifm;

import cic.cs.unb.ca.flow.FlowMgr;
import cic.cs.unb.ca.jnetpcap.*;
import cic.cs.unb.ca.jnetpcap.worker.FlowGenListener;
import org.apache.commons.io.FilenameUtils;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapClosedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import cic.cs.unb.ca.jnetpcap.worker.InsertCsvRow;
import swing.common.SwingUtils;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static cic.cs.unb.ca.Sys.FILE_SEP;

public class Cmd {

    public static final Logger logger = LoggerFactory.getLogger(Cmd.class);
    private static final String DividingLine = "-------------------------------------------------------------------------------";

    public static void main(String[] args) {
        if (args.length > 0 && args[0].equalsIgnoreCase("-live")) {
            if (args.length < 2) {
                logger.info("Please specify an output directory for live capture, e.g., -live /tmp/captures");
                return;
            }
            startLiveCapture(args[1]);
        } else {
            startOfflineProcessing(args);
        }
    }

    private static void startLiveCapture(String outputDir) {
        logger.info("Starting live capture...");
        File outDir = new File(outputDir);
        if (!outDir.exists()) {
            logger.info("Output directory {} does not exist, creating it.", outputDir);
            if (!outDir.mkdirs()) {
                logger.error("Failed to create output directory {}.", outputDir);
                return;
            }
        }

        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;
        final FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);

        List<PcapIf> alldevs = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            logger.error("Can't read list of devices, error is {}", errbuf.toString());
            return;
        }

        logger.info("Found {} network interfaces:", alldevs.size());
        for (int i = 0; i < alldevs.size(); i++) {
            logger.info("  {}. {}", i + 1, alldevs.get(i).getName());
        }

        // Schedule task to dump flows every 60 seconds
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleAtFixedRate(() -> {
            try {
                String timestamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
                String filename = outputDir + FILE_SEP + "capture-" + timestamp + ".csv";
                logger.info("Dumping flows to {}...", filename);
                flowGen.dumpLabeledCurrentFlow(filename, FlowFeature.getHeader());
                // Do NOT clear flows here, as dumpLabeledCurrentFlow appends.
                // A better approach would be to get flows, write them, then clear.
                // For now, let's stick to the plan of clearing after dump.
                // After re-reading dumpLabeledCurrentFlow, it opens in append mode if file exists,
                // but we create a new file each time. So clearing is correct.
                flowGen.clearCurrentFlows();
                logger.info("Flows dumped successfully.");
            } catch (Exception e) {
                logger.error("Error dumping flows", e);
            }
        }, 60, 60, TimeUnit.SECONDS);

        for (PcapIf device : alldevs) {
            Thread captureThread = new Thread(() -> {
                try {
                    int snaplen = 64 * 1024;
                    int flags = Pcap.MODE_PROMISCUOUS;
                    int timeout = 10 * 1000;
                    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

                    if (pcap == null) {
                        logger.error("Error while opening device for capture: {}", errbuf.toString());
                        return;
                    }

                    logger.info("Capturing on device: {}", device.getName());
                    PacketReader packetReader = new PacketReader(pcap);

                    while (true) {
                        try {
                            BasicPacketInfo basicPacket = packetReader.nextPacket();
                            if (basicPacket != null) {
                                synchronized (flowGen) {
                                    flowGen.addPacket(basicPacket);
                                }
                            }
                        } catch (PcapClosedException e) {
                            break; 
                        }
                    }
                    pcap.close();
                } catch (Exception e) {
                    logger.error("Exception in capture thread for device " + device.getName(), e);
                }
            });
            captureThread.start();
        }
    }

    private static void startOfflineProcessing(String[] args) {
        long flowTimeout = 120000000L;
        long activityTimeout = 5000000L;
        String pcapPath;
        String outPath;

        if (args.length < 1) {
            logger.info("Please select pcap file or directory!");
            return;
        }
        pcapPath = args[0];
        File in = new File(pcapPath);

        if (!in.exists()) {
            logger.info("The pcap file or folder does not exist! -> {}", pcapPath);
            return;
        }

        if (args.length < 2) {
            logger.info("Please select output folder!");
            return;
        }
        outPath = args[1];
        File out = new File(outPath);
        if (out.isFile()) {
            logger.info("The output path must be a directory! -> {}", outPath);
            return;
        }
        if (!out.exists()) {
            if (!out.mkdirs()) {
                logger.info("Could not create output directory! -> {}", outPath);
                return;
            }
        }

        logger.info("You select: {}", pcapPath);
        logger.info("Out folder: {}", outPath);

        if (in.isDirectory()) {
            readPcapDir(in, outPath, flowTimeout, activityTimeout);
        } else {
            if (!SwingUtils.isPcapFile(in)) {
                logger.info("Please select a pcap file!");
            } else {
                logger.info("CICFlowMeter received 1 pcap file");
                readPcapFile(in.getPath(), outPath, flowTimeout, activityTimeout);
            }
        }
    }

    private static void readPcapDir(File inputPath, String outPath, long flowTimeout, long activityTimeout) {
        if (inputPath == null || outPath == null) {
            return;
        }
        File[] pcapFiles = inputPath.listFiles(SwingUtils::isPcapFile);
        int file_cnt = pcapFiles.length;
        System.out.println(String.format("CICFlowMeter found :%d pcap files", file_cnt));
        for (int i = 0; i < file_cnt; i++) {
            File file = pcapFiles[i];
            if (file.isDirectory()) {
                continue;
            }
            int cur = i + 1;
            System.out.println(String.format("==> %d / %d", cur, file_cnt));
            readPcapFile(file.getPath(), outPath, flowTimeout, activityTimeout);
        }
        System.out.println("Completed!");
    }

    private static void readPcapFile(String inputFile, String outPath, long flowTimeout, long activityTimeout) {
        if (inputFile == null || outPath == null) {
            return;
        }
        String fileName = FilenameUtils.getName(inputFile);

        if (!outPath.endsWith(FILE_SEP)) {
            outPath += FILE_SEP;
        }

        File saveFileFullPath = new File(outPath + fileName + FlowMgr.FLOW_SUFFIX);

        if (saveFileFullPath.exists()) {
            if (!saveFileFullPath.delete()) {
                System.out.println("Save file can not be deleted");
            }
        }

        FlowGenerator flowGen = new FlowGenerator(true, flowTimeout, activityTimeout);
        flowGen.addFlowListener(new FlowListener(fileName, outPath));
        boolean readIP6 = false;
        boolean readIP4 = true;
        PacketReader packetReader = new PacketReader(inputFile, readIP4, readIP6);

        System.out.println(String.format("Working on... %s", fileName));

        int nValid = 0;
        int nTotal = 0;
        int nDiscarded = 0;
        long previousTimestamp = 0L;
        long currentTimestamp = 0L;
        boolean disordered = false;
        long idDisorderedPacket = 0L;

        while (true) {
            try {
                BasicPacketInfo basicPacket = packetReader.nextPacket();
                if (basicPacket == null) { // End of file
                    break;
                }
                nTotal++;
                
                currentTimestamp = basicPacket.getTimeStamp();
                if (!(disordered) && (previousTimestamp > currentTimestamp)) {
                    idDisorderedPacket = basicPacket.getId();
                    disordered = true;
                    System.out.println(DividingLine);
                    System.out.println("/!\\ The pcap file contains disordered packets ! The network flows may be incorrect.");
                    System.out.println(String.format("The packet with ID %d is the first disordered one.", idDisorderedPacket));
                    System.out.println("Please order your pcap file and run the tool again.");
                    System.out.println(DividingLine);
                } else {
                    previousTimestamp = currentTimestamp;
                }

                flowGen.addPacket(basicPacket);
                nValid++;

            } catch (PcapClosedException e) {
                break;
            }
        }

        flowGen.dumpLabeledCurrentFlow(saveFileFullPath.getPath(), FlowFeature.getHeader());
        long lines = SwingUtils.countLines(saveFileFullPath.getPath());

        System.out.println(String.format("%s is done. total %d flows ", fileName, lines));
        System.out.println(String.format("Packet stats: Total=%d,Valid=%d,Discarded=%d", nTotal, nValid, nDiscarded));
        System.out.println(DividingLine);
    }

    static class FlowListener implements FlowGenListener {
        private String fileName;
        private String outPath;
        private long cnt;

        public FlowListener(String fileName, String outPath) {
            this.fileName = fileName;
            this.outPath = outPath;
        }

        @Override
        public void onFlowGenerated(BasicFlow flow) {
            String flowDump = flow.dumpFlowBasedFeaturesEx();
            List<String> flowStringList = new ArrayList<>();
            flowStringList.add(flowDump);
            InsertCsvRow.insert(FlowFeature.getHeader(), flowStringList, outPath, fileName + FlowMgr.FLOW_SUFFIX);
            cnt++;
            System.out.print(String.format("%s -> %d flows \r", fileName, cnt));
        }
    }
}
