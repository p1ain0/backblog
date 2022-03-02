# Taichi

## 安装

pip install taichi

## Taichi程序的组成

Data Computation Visualization

### 初始化

```python
import taichi as ti
ti.init(arch=ti.gpu) # The entry point for All Taichi project
```

arch:
| | CPU | CUDA | OpenGL | Apple Metal | Vulkan |
|-| -- | -- | -- | -- | -- |
| Window | Yes | Yes | Yes | No | WIP |
| Linux | Yes | Yes | Yes | No | WIP |
| MacOS | Yes | No  | No | Yes | WIP |

taichi-scope

```python
import taichi as ti
ti.init(arch=ti.gpu)

@ti.kernel
def fun():
    print("This is now a Tachi kernel")
fun()
```

### taichi Data

基础类型：
signed integers : ti.i8, ti.i16, ti.i32, ti.i64
unsigned intergers : ti.u8, ti.u16, ti.u32, ti.u64
floating points : ti.f32, ti.f64

| Type | i8 | i16 | i32 | i64 | u8 | u16 | u32 | u64 | f32 | f64 |
| - | - | - | - | - | - | - | - | - | - | - |
| CPU/CUDA | yes | yes | yes | yes | yes | yes | yes | yes | yes | yes |
| Metal | yes | yes | yes | No | yes | yes | yes | No | yes | No |
| OpenGL | No | No | Yes | Ext | No | No | No | No | yes | yes |

ti.init(default_fp=ti.f32)
ti.init(default_fp=ti.f64)

ti.init(default_fp=ti.i32)
ti.init(default_fp=ti.i64)

#### type cast

variable = ti.cast(variable, type)

#### Compound type

```python
vec3f = ti.types.vector(3, ti.f32)
mat2f = ti.types.matrix(2, 2, ti.f32)
ray = ti.types.struct(ro=vec3f, rd=vec3f, l=ti.f32)

也可以使用taichi里边内置的类型：
ti.Vector()
ti.Matrix()
ti.Struct()
```

ti.field

### taichi计算核

最外层的循环会并行计算

参数：
1.最多8个参数
2.从python作用域传到taichi作用域
3.必须是type-hinted
4.scalar only
5.pass by value

返回值：
1.可以返回不返回
2.从python作用域传到taichi作用域
3.必须是type-hinted

函数调用：
taichi函数只能从taichi scope中被调用

Math ops：

### taichi可视化

2D：ti.GUI

    set your window: gui=ti.GUI("Title", res=(1024,768))
    paint on a window: gui.set_image()
    elements: gui.circles(),gui.lines(), gui.rects(), gui.triangles()...
    widgets: gui.button(), gui.slider(), gui.text()...
    event: gui.get_events(), gui.get_key_event(), gui.running...

### 面向对象编程

```python
@ti.data_oriented
class ...
```

## 程序动画

步骤：

    1.setup your canvas
    2.put some colors on your canvas
    3.Draw a basic unit
    4.Repeat the basic units:tiles and fractals
    5.Animate your picture
    6.Introduce some randomness

