# DramaClaw · Activation manager

Backend quản lý mã dùng một lần, triển khai **GitHub → Vercel → PostgreSQL**. Không đặt tài khoản AI, cookie hoặc dự án DramaClaw vào repository này.

## Triển khai

1. Import repository này vào Vercel, chọn framework **FastAPI**, root directory là gốc repo. Vercel tự nhận `app.py`.
2. Trong Storage/Marketplace, kết nối PostgreSQL (ví dụ Neon), bật `DATABASE_URL` cho Production. Dùng connection string pooled có TLS. Không dùng SQLite trên Vercel.
3. Đặt hai Environment Variables Production từ file bí mật chỉ có trên máy đóng gói:
   - `LICENSE_SIGNING_KEY`: khóa Ed25519 raw 32 byte, mã hóa Base64.
   - `LICENSE_ADMIN_TOKEN`: chuỗi ngẫu nhiên ít nhất 32 ký tự.
4. Deploy/redeploy. Mở URL deployment, nhập token quản trị. Lần kết nối đầu tạo bảng database (`POST /admin/init`).
5. Tạo key, lưu key đầy đủ ngay khi tạo. Database chỉ giữ hash và prefix, không thể xem lại key đầy đủ.
6. Điền URL HTTPS này vào `desktop/activation.json` của bộ chạy trước khi gửi cho nhân viên. `public_key` phải tương ứng khóa ký ở Vercel.

Chỉ đưa mã nguồn này lên GitHub. Không đưa `.owner-secrets.json`, `.env`, database URL hoặc khóa ký vào repo. Tài khoản GitHub/Vercel/Neon và các giới hạn/gói dịch vụ thuộc chủ triển khai; không có bí mật nào trong trang HTML.

## Quy tắc

- Một key kích hoạt một mã máy (SHA-256 Windows MachineGuid, không gửi thông tin phần cứng thô).
- Cập nhật nguyên tử ở database ngăn hai máy nhận cùng một key. Gửi lại trên **cùng máy** trả lại giấy phép cũ, hữu ích khi mất phản hồi mạng.
- Giấy phép ký Ed25519, client kiểm tra offline bằng khóa công khai. Giữ khóa ký an toàn và sao lưu riêng.
- Key chưa dùng có thể khóa. Giấy phép đã cấp **không thu hồi từ xa**, không hết hạn và không đổi máy. Cần tính năng này thì phải chuyển sang kiểm tra online định kỳ trước khi cấp giấy phép thực tế.
- Không cần nhập admin token ở client. Trang quản trị giữ token trong bộ nhớ trang; tải lại cần nhập lại.
- Bật bảo vệ rate limit/WAF cho `/v1/activate` và `/admin/*` trên Vercel theo lưu lượng công ty. Key có 192 bit ngẫu nhiên; không dùng key tự đặt dễ đoán.
- Dùng database riêng cho Production và Preview. Không gắn database key thật vào preview hoặc nhánh không tin cậy.

Kiểm tra dịch vụ: `GET /healthz`. Không tự động tạo key hoặc tự động mở lại key đã dùng sau lỗi.

Tài liệu nền tảng: [FastAPI trên Vercel](https://vercel.com/docs/frameworks/backend/fastapi), [PostgreSQL qua Marketplace](https://vercel.com/docs/postgres).
