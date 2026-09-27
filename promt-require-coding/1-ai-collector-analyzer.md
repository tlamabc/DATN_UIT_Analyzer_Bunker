# Role & Goal
Bạn là Senior Backend & Security Developer. Hãy viết toàn bộ mã nguồn Python cho module **AI Collector & Analyzer** được đặt bên trong thư mục `ai-collector-analyzer/`.

# Bối cảnh hệ thống
- Hệ thống tích hợp WAF (BunkerWeb) -> Thu thập log -> Gửi sang **vMaaS** (thay thế Ollama để phân tích bằng AI) -> Lưu vào **PostgreSQL**.
- File mẫu kết nối vMaaS đã có sẵn ở thư mục gốc (`connect_vMaaS.py`), hãy tham khảo cấu trúc đó để gọi API vMaaS.
- Kết nối cơ sở dữ liệu và cấu hình đọc qua biến môi trường (`.env` ở thư mục gốc).

# Yêu cầu kỹ thuật chi tiết
1. **Database Connection & Initialization**:
   - Sử dụng thư viện `psycopg2` hoặc `SQLAlchemy` để kết nối vào PostgreSQL dựa trên các biến môi trường: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`.
   - Tự động tạo bảng `security_events` nếu chưa tồn tại với các trường: `id` (PK, Serial), `timestamp` (Timestamp), `client_ip` (VARCHAR), `raw_log` (TEXT), `attack_type` (VARCHAR), `severity` (VARCHAR - Critical/High/Medium/Low), `recommendation` (TEXT).

2. **AI Collector**:
   - Viết một tiến trình (script) đọc các sự kiện log bảo mật từ BunkerWeb (có thể đọc từ file audit log được mount qua volume `/var/log/bunkerweb` hoặc nhận qua mô phỏng API).

3. **AI Analyzer & vMaaS Integration**:
   - Đóng gói log thô thành payload chuẩn, gọi API tới **vMaaS** để nhờ AI phân tích xem log đó thuộc loại tấn công nào, mức độ nguy hiểm ra sao và đề xuất hướng xử lý.
   - Nhận kết quả JSON trả về từ vMaaS và thực thi lệnh `INSERT` lưu dữ liệu vào bảng `security_events` trong PostgreSQL.

4. **Đóng gói Docker**:
   - Viết một `Dockerfile` gọn nhẹ (base image python:3.10-slim) cho service này.
   - Viết file `requirements.txt` chứa các thư viện cần thiết (`requests`, `psycopg2-binary`, `python-dotenv`, v.v.).