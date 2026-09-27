# Role & Goal
Bạn là Senior UI/UX Designer kết hợp chuyên gia bảo mật SOC (Security Operations Center). Hãy thiết kế chi tiết kiến trúc giao diện, luồng trải nghiệm người dùng (UX) và quy chuẩn giao diện (UI Design System) cho module **Dashboard / Report** của hệ thống bảo mật vMaaS, được đặt trong thư mục `dashboard-report/` của đồ án tốt nghiệp.

# Bối cảnh hệ thống
- Giao diện trực quan hóa dữ liệu bảo mật cấp doanh nghiệp dành cho Quản trị viên SOC theo dõi, kiểm soát và điều tra các sự kiện tấn công web được phân tích tự động bởi vMaaS AI và lưu trữ tại PostgreSQL.

# Yêu cầu thiết kế UI/UX phong cách SOC chuyên nghiệp
1. **Thiết kế giao diện & Chủ đề (Theme & Styling)**:
   - **Cyber-Security Dark Mode**: Sử dụng tông màu đặc trưng của các trung tâm giám sát an ninh (Nền tối sâu `#0B0F19`, các khối thẻ sử dụng hiệu ứng Glassmorphism với viền sáng mờ tinh tế `#1F2937`).
   - **Hệ thống màu sắc cảnh báo chuẩn SOC (Severity Color Coding)**:
     - `Critical`: Đỏ rực (`#F87171`) kèm hiệu ứng nhấn mạnh trực quan.
     - `High`: Cam sáng (`#FB923C`).
     - `Medium`: Vàng cảnh báo (`#FBBF24`).
     - `Low` / `Info`: Xanh dương/Xanh ngọc an toàn (`#34D399`).
   - Bố cục lưới (Grid Layout) phân chia rõ ràng các vùng: Thanh điều khiển bên (Sidebar Control), Khối chỉ số tổng quan (Metrics Overview), Vùng trực quan hóa biểu đồ (Analytics Charts), và Bảng nhật ký sự kiện chuyên sâu (Security Events Matrix).

2. **Quy chuẩn tính năng & Trải nghiệm tương tác (Features & UX Flow)**:
   - **Sidebar (Trung tâm điều khiển nhanh)**:
     - Trạng thái kết nối cơ sở dữ liệu thời gian thực (Live DB Status Indicator).
     - Bộ lọc không gian thời gian (Time-range selector linh hoạt).
     - Bộ lọc đa tiêu chí chồng (Multi-select theo Mức độ nghiêm trọng, Loại tấn công và thanh tìm kiếm tự do theo Địa chỉ IP nguồn).
     - Nút làm mới dữ liệu thủ công (`Refresh Data`).
   - **Metrics Overview (Thẻ chỉ số trọng yếu)**:
     - Thẻ chỉ số dạng nổi khối hiển thị: Tổng số sự kiện chặn, Tổng cảnh báo mức độ nguy hiểm cao (Critical/High), Số lượng IP tấn công độc hại duy nhất (Unique Attackers), và Tỷ lệ ngăn chặn của WAF.
   - **Analytics Charts (Biểu đồ phân tích trực quan)**:
     - Biểu đồ phân bổ tỷ lệ hình thức tấn công (Donut Chart) với chú thích trực quan, màu sắc tương phản cao.
     - Biểu đồ vùng/đường (Area/Line Chart) thể hiện xu hướng tần suất tấn công phân bổ theo trục thời gian thực.
   - **Security Events Table & AI Incident Inspector (Bảng nhật ký & Trình kiểm tra sự cố AI)**:
     - Bảng dữ liệu log dạng rút gọn, hỗ trợ cuộn mượt mà, hiển thị rõ mốc thời gian, IP, dạng tấn công và mức độ.
     - **Trình kiểm tra chi tiết (Incident Inspector)**: Cho phép chọn/click vào từng bản ghi sự kiện để mở rộng khung phân tích sâu, hiển thị tường minh chuỗi `Raw Log` payload gốc và **Báo cáo đề xuất khắc phục chi tiết bằng tiếng Việt** do vMaaS AI tổng hợp dưới dạng khung Markdown nổi bật, dễ đọc.
   - **Báo cáo & Trích xuất (Reporting & Export)**:
     - Chức năng kết xuất dữ liệu đang lọc thành file báo cáo định dạng chuẩn CSV phục vụ công tác kiểm toán hoặc lưu trữ hồ sơ đồ án.

3. **Yêu cầu kỹ thuật & Đóng gói triển khai**:
   - Kiến trúc module sử dụng `Streamlit`, `Pandas`, `Plotly`, và kết nối PostgreSQL qua `psycopg2-binary` (cấu hình thông số qua `os.environ`).
   - Cung cấp file cấu hình `requirements.txt` đầy đủ các thư viện phụ thuộc.
   - Xây dựng file `Dockerfile` tối ưu, gọn nhẹ, mở sẵn cổng tiêu chuẩn `8501` để tích hợp mượt mà vào hệ thống `docker-compose` tổng thể của đồ án.