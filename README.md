# Context-Aware IaC Security Gate

Repository này chuẩn bị tích hợp CI/CD cho prototype ưu tiên xử lý phát hiện bảo mật trong Terraform. Dự án nghiên cứu dùng ngữ cảnh kỹ thuật và ngữ cảnh nghiệp vụ để sắp xếp các finding mà scanner đã phát hiện.

## Prototype tham chiếu

Luồng xử lý theo D-039:

1. Tạo bản sao Terraform riêng để chạy validation, rồi quét cấu hình với Checkov.
2. Chuẩn hóa finding và trích xuất contextual features theo phạm vi đã duyệt. Giữ các finding ngoài phạm vi chấm điểm trong báo cáo.
3. Dùng Random Forest deployment model D-038 để tính điểm ưu tiên cho finding có đủ dữ liệu đầu vào. Score phục vụ xếp hạng trong lượt quét. Đánh giá khoa học được quản lý riêng trong repository nghiên cứu.
4. Ghi kết quả Gate cùng báo cáo và checksum.

| Trạng thái Gate | Ý nghĩa trong prototype D-039 |
| --- | --- |
| `PASS` (exit 0) | Xử lý hoàn tất và lượt quét có 0 failed finding. |
| `REVIEW` (exit 10) | Xử lý hoàn tất và có ít nhất một failed finding, kể cả finding chưa được chấm điểm. |
| `ERROR` (exit 20) | Việc xử lý chưa hoàn tất hoặc kết quả không đủ tin cậy. |

Gate decision dựa trên tình trạng hoàn tất và failed findings. Điểm Random Forest quyết định thứ tự ưu tiên trong danh sách được chấm.

## Trạng thái tích hợp

Repository nghiên cứu lưu phương pháp, dữ liệu, model và hồ sơ đánh giá. Repository CI này dành cho cấu hình tích hợp và bước thử runner. Workflow [Runner smoke](.github/workflows/runner-smoke.yml) chuẩn bị kiểm Linux x64, phiên bản Python sẵn có và cấu trúc workspace trên GitHub-hosted Ubuntu. Chưa có kết quả smoke test trên GitHub.

Một workflow Security Gate trong tương lai sẽ cần release đã xác thực và quyền phân phối đã được duyệt. Trong giai đoạn này, Security Gate ở mức `ADVISORY_ONLY`. Phạm vi dự án không bao gồm `terraform apply` hoặc triển khai hạ tầng cloud production.
