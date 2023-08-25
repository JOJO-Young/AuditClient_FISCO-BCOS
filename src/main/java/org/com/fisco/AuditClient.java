package org.com.fisco;

import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ClassPathResource;
import org.apache.commons.io.input.Tailer;
import org.apache.commons.io.input.TailerListenerAdapter;
import org.fisco.bcos.sdk.BcosSDK;
import org.fisco.bcos.sdk.client.Client;
import org.fisco.bcos.sdk.crypto.keypair.CryptoKeyPair;

public class AuditClient {
    static Logger logger = LoggerFactory.getLogger(AuditClient.class);
    private BcosSDK sdk;
    private Client client;
    private CryptoKeyPair cryptoKeyPair;

    private void initialize() {
        try {
            String configFile = Objects.requireNonNull(BcosSDK.class.getClassLoader().getResource("config-example.toml")).getPath();
            sdk = BcosSDK.build(configFile);
            // 初始化可向群组1发交易的Client
            client = sdk.getClient(1);
            cryptoKeyPair = client.getCryptoSuite().createKeyPair();
            client.getCryptoSuite().setCryptoKeyPair(cryptoKeyPair);
            logger.debug("create client for group1, account address is " + cryptoKeyPair.getAddress());
        } catch (Exception e) {
            logger.error(" Initialize exception, error message is {}", e.getMessage());
            System.out.printf(" Initialize failed, error message is %s\n", e.getMessage());
        }
    }

    private void deployAssetAndRecordAddr() {
        try {
            AuditHashContract sample = AuditHashContract.deploy(client, cryptoKeyPair);
            System.out.println(" deploy Contract success, contract address is " + sample.getContractAddress());
            recordAuditAddr(sample.getContractAddress());
        } catch (Exception e) {
            logger.error(" Deploy exception, error message is {}", e.getMessage());
            System.out.println(" Deploy contract failed, error message is  " + e.getMessage());
        }
    }

    private void recordAuditAddr(String address) throws IOException {
        Properties prop = new Properties();
        prop.setProperty("address", address);
        final Resource contractResource = new ClassPathResource("contract.properties");
        FileOutputStream fileOutputStream = new FileOutputStream(contractResource.getFile());
        prop.store(fileOutputStream, "contract address");
    }

    private String loadAuditAddr() throws Exception {
        // load contact address from contract.properties
        Properties prop = new Properties();
        final Resource contractResource = new ClassPathResource("contract.properties");
        prop.load(contractResource.getInputStream());

        String contractAddress = prop.getProperty("address");
        if (contractAddress == null || contractAddress.trim().isEmpty()) {
            throw new Exception(" Load Audit contract address failed, please deploy it first. ");
        }
        logger.info(" Load Audit address from contract.properties, address is {}", contractAddress);
        return contractAddress;
    }

    private void the_saveAuditHash(String hash, BigInteger ctID, BigInteger flowStartSec) {
        try {
            String contractAddress = loadAuditAddr();
            AuditHashContract save_event = AuditHashContract.load(contractAddress, client, cryptoKeyPair);
            save_event.saveAuditHash(hash, ctID, flowStartSec);
            System.out.println("save audit information success!\nctID is " + ctID.toString() + "\nflowStartSec is " + flowStartSec.toString() + "\nhashcode is " + hash);
        } catch (Exception e) {
            logger.error(" SaveAuditHash exception, error message is {}", e.getMessage());
            System.out.printf(" SaveAuditHash failed, error message is %s\n", e.getMessage());
        }
    }

    private String the_getAuditHash(BigInteger ctID, BigInteger flowStartSec) {
        try {
            String contractAddress = loadAuditAddr();
            AuditHashContract get_event = AuditHashContract.load(contractAddress, client, cryptoKeyPair);
            return get_event.getAuditHash(ctID, flowStartSec);
        } catch (Exception e) {
            logger.error(" GetAuditHash exception, error message is {}", e.getMessage());
            System.out.printf(" GetAuditHash failed, error message is %s\n", e.getMessage());
            return null;
        }
    }

    private Boolean the_verifyAuditHash(String hash, BigInteger ctID, BigInteger flowStartSec) {
        try {
            String contractAddress = loadAuditAddr();
            AuditHashContract verify_event = AuditHashContract.load(contractAddress, client, cryptoKeyPair);
            return verify_event.verifyAuditHash(hash, ctID, flowStartSec);
        } catch (Exception e) {
            logger.error(" VerifyAuditHash exception, error message is {}", e.getMessage());
            System.out.printf(" VerifyAuditHash failed, error message is %s\n", e.getMessage());
            return null;
        }
    }

    private void the_watchAndUploadLog(String logFilePath) {
        try {
            File logFile = new File(logFilePath);
            if (!logFile.exists()) {
                System.out.println("WatchAndUploadLog failed, 待监测日志文件不存在");
                return;
            }

            LogFileListener listener = new LogFileListener();
            Tailer tailer = new Tailer(logFile, listener, 50);

            Thread tailerThread = new Thread(tailer);
            tailerThread.start();
            System.out.println("监测已开始，按回车键停止监测...");
            while (System.in.available() <= 0) {
                Thread.sleep(100);
            }
            tailer.stop();
            tailerThread.join();
            System.out.println("文件监测已退出...");
        } catch (Exception e) {
            logger.error(" WatchAndUploadLog exception, error message is {}", e.getMessage());
            System.out.printf(" WatchAndUploadLog failed, error message is %s\n", e.getMessage());
        }
    }

    private class LogFileListener extends TailerListenerAdapter {
        @Override
        public void handle(String line) {
            try {
                Map<String, String> auditInfo = parseAuditInfo(line);
                String hash = calculateHash(line);
                BigInteger ctID = new BigInteger(auditInfo.get("'ct.id'"));
                BigInteger flowStartSec = new BigInteger(auditInfo.get("'flow.start.sec'"));
                the_saveAuditHash(hash, ctID, flowStartSec);
            } catch (Exception e) {
                logger.error(" LogFileListener exception, error message is {}", e.getMessage());
                System.out.printf(" LogFileListener failed, error message is %s\n", e.getMessage());
            }
        }
    }

    private String calculateHash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hashHex = new StringBuilder();
        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hashHex.append('0');
            hashHex.append(hex);
        }
        return hashHex.toString();
    }

    private Map<String, String> parseAuditInfo(String line) {
        // 解析日志行并返回一个包含审计信息的Map
        Map<String, String> auditInfo = new HashMap<>();
        String[] keyValuePairs = line.split(", |\\{|\\}");
        for (String pair : keyValuePairs) {
            String[] keyValue = pair.split(": ");
            if (keyValue.length == 2) {
                String key = keyValue[0].trim();
                String value = keyValue[1].trim();
                auditInfo.put(key, value);
            }
        }
        return auditInfo;
    }

    public static void Usage() {
        System.out.println(" Usage:");
        System.out.println("\t java -cp conf/:lib/*:apps/* org.com.fisco.AuditClient deploy");
        System.out.println("\t java -cp conf/:lib/*:apps/* org.com.fisco.AuditClient save hash ctID flowStartSec");
        System.out.println("\t java -cp conf/:lib/*:apps/* org.com.fisco.AuditClient verify hash ctID flowStartSec");
        System.out.println("\t java -cp conf/:lib/*:apps/* org.com.fisco.AuditClient get ctID flowStartSec");
        System.out.println("\t java -cp conf/:lib/*:apps/* org.com.fisco.AuditClient watch filePath");
        System.exit(0);
    }

    public static void main(String[] args) {
        AuditClient client = new AuditClient();
        client.initialize();

        switch (args[0]) {
            case "deploy":
                client.deployAssetAndRecordAddr();
                break;
            case "save":
                client.the_saveAuditHash(args[1], new BigInteger(args[2]), new BigInteger(args[3]));
                break;
            case "verify":
                if (Boolean.TRUE.equals(client.the_verifyAuditHash(args[1], new BigInteger(args[2]), new BigInteger(args[3]))))
                    System.out.println("PASS");
                else System.out.println("FAIL");
                break;
            case "get":
                System.out.println(client.the_getAuditHash(new BigInteger(args[1]), new BigInteger(args[2])));
                break;
            case "watch":
                client.the_watchAndUploadLog(args[1]);
                break;
            default:
                Usage();
        }

        System.exit(0);
    }
}
