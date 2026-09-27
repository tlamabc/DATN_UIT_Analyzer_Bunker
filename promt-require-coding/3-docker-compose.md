# Role & Goal
Bạn là DevOps Engineer. Hãy viết hoặc hoàn thiện file `docker-compose.yml` nằm ở thư mục gốc của project để liên kết toàn bộ hệ thống gồm PostgreSQL, AI Collector & Analyzer, và Dashboard Report.

# Yêu cầu kỹ thuật chi tiết
1. **Cấu trúc Services**:
   - **`postgres_db`**: Sử dụng image `postgres:15-alpine`, cấu hình biến môi trường lấy từ `.env`, mở cổng `5432` và gắn Persistent Volume (`postgres_data`) để dữ liệu không bị mất khi restart container.
   - **`ai_collector_analyzer`**: Build từ thư mục `./ai-collector-analyzer`, cấu hình phụ thuộc vào `postgres_db`, đọc biến môi trường kết nối DB và vMaaS, mount thư mục log hệ thống (`/var/log/bunkerweb`) từ máy host vào container ở chế độ đọc (`ro`).
   - **`dashboard_report`**: Build từ thư mục `./dashboard-report`, mở port `8501:8501`, phụ thuộc vào `postgres_db`, kết nối vào database chung.

2. **Networking & Volumes**:
   - Cấu hình chung một Docker Network (ví dụ: `waf_ai_net`) để các service liên lạc nội bộ với nhau qua tên service (hostname).
   - Khai báo đầy đủ các Docker Volumes cần thiết.