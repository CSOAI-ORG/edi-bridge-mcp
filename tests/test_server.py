import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

X12="ISA*00*          *00*          *ZZ*S              *ZZ*R              *240625*1200*U*00401*1*0*P*>~GS*PO*S*R*20240625*1200*1*X*004010~ST*850*0001~SE*3*0001~"
def test_parse():
    p=server.parse_edi(X12); assert p.standard=="X12"; assert p.transaction=="850"
def test_govern():
    assert server.govern_edi(X12).frameworks
