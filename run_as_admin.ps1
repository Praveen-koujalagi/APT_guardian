# PowerShell script to run packet capture test with admin privileges
Write-Host "🚀 APT Guardian Admin Test Script" -ForegroundColor Green
Write-Host "=" * 50 -ForegroundColor Cyan

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if ($isAdmin) {
    Write-Host "✅ Running with Administrator privileges" -ForegroundColor Green
    Write-Host ""
    Write-Host "Running packet capture test..." -ForegroundColor Yellow
    
    # Run the test
    python test_packet_capture.py
    
    Write-Host ""
    Write-Host "Test completed!" -ForegroundColor Green
} else {
    Write-Host "❌ Administrator privileges required!" -ForegroundColor Red
    Write-Host ""
    Write-Host "To fix packet capture issues:" -ForegroundColor Yellow
    Write-Host "1. Right-click PowerShell and select 'Run as administrator'" -ForegroundColor White
    Write-Host "2. Navigate to your project directory" -ForegroundColor White
    Write-Host "3. Run: python test_packet_capture.py" -ForegroundColor White
    Write-Host ""
    Write-Host "Or use the Streamlit app:" -ForegroundColor Yellow
    Write-Host "streamlit run app.py" -ForegroundColor White
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
