# Role & Goal
Bạn là Full-stack Developer. Hãy viết toàn bộ mã nguồn cho module **Dashboard / Report** được đặt bên trong thư mục `dashboard-report/`.

# Bối cảnh hệ thống
- Giao diện trực quan hóa dữ liệu bảo mật (SOC Dashboard) dành cho quản trị viên xem các sự kiện tấn công đã được **vMaaS** phân tích và lưu vào cơ sở dữ liệu **PostgreSQL**.

# Yêu cầu kỹ thuật chi tiết
1. **Công nghệ sử dụng**:
   - Sử dụng **Streamlit** kết hợp với **Pandas** để xây dựng giao diện nhanh chóng, trực quan và hiện đại.
   - Kết nối trực tiếp vào **PostgreSQL** (lấy thông số kết nối qua biến môi trường `os.environ`).

2. **Tính năng trên Dashboard**:
   - **Metrics Overview (Thẻ chỉ số tổng quan)**: Hiển thị tổng số sự kiện tấn công bị chặn, số lượng cảnh báo mức độ Critical/High.
   - **Charts (Biểu đồ trực quan)**: Biểu đồ phân loại các dạng tấn công phổ biến (XSS, SQL Injection, Path Traversal, v.v.) và biểu đồ phân bổ theo thời gian.
   - **Security Events Table (Bảng chi tiết)**: Bảng dữ liệu hiển thị lịch sử log chi tiết kèm theo IP nguồn, loại tấn công, mức độ nghiêm trọng và đề xuất khắc phục từ vMaaS.
   - **Real-time Refresh**: Có nút bấm "Refresh" để làm mới dữ liệu từ database.

3. **Đóng gói Docker**:
   - Viết `Dockerfile` cho service Dashboard, mở port chuẩn `8501`.
   - Viết file `requirements.txt` (`streamlit`, `pandas`, `psycopg2-binary`, v.v.).