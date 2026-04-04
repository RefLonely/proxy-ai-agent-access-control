"""
外部导入检查测试
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_external_imports():
    """测试外部库是否可以正常导入"""
    try:
        import networkx
        print(f"✅ NetworkX 版本: {networkx.__version__}")
        
        import numpy
        print(f"✅ NumPy 版本: {numpy.__version__}")
        
        import scipy
        print(f"✅ SciPy 版本: {scipy.__version__}")
        
        import dataclasses_json
        print(f"✅ Dataclasses JSON 版本: {dataclasses_json.__version__}")
        
        return True
        
    except Exception as e:
        print(f"❌ 外部库导入失败: {e}")
        import traceback
        print(f"详细错误信息: {traceback.format_exc()}")
        return False

def test_core_modules():
    """测试核心模块是否可以正常导入"""
    try:
        from src import AgenticAccessController
        from src.models import Agent, AccessRequest, AccessAction, DecisionOutcome
        
        print("✅ 核心模块导入成功")
        return True
        
    except Exception as e:
        print(f"❌ 核心模块导入失败: {e}")
        import traceback
        print(f"详细错误信息: {traceback.format_exc()}")
        return False


def run_import_checks():
    """运行导入检查"""
    print("开始外部依赖导入检查")
    print("=" * 60)
    
    success = False
    
    # 首先检查外部库
    print("\n外部库检查:")
    external_ok = test_external_imports()
    
    # 然后检查核心模块
    print("\n核心模块检查:")
    core_ok = test_core_modules()
    
    print("\n" + "=" * 60)
    
    if external_ok and core_ok:
        print("✅ 所有导入检查通过")
        success = True
    else:
        print("❌ 部分导入检查失败")
        success = False
    
    return success


if __name__ == "__main__":
    success = run_import_checks()
    sys.exit(0 if success else 1)
