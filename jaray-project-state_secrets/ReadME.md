一、数字加密技术

1)         单钥密码体制/对称密码体制

指加密密钥和解密密钥为同一密钥的密码体制，因此通信双方必须共同持有该密钥。

DES、AES是一种对称密码体制

2)         双钥密码体制/非对称密码体制/公开密钥密码体制

指加密密钥和解密密钥为两个不同密钥的密码体制；这两个密钥之间存在着互相依存关系，即其中任一个密钥加密的信息只能用另一个密钥进行解密。

RSA、DSA是一种公钥密码体制。

3)         总结：

对称密码和公钥密码都需要保证密钥的安全，不同之处在于密钥的管理和分发上面。在对称密码中，必须要有一种可靠的手段将加密密钥（同时也是解密密钥）告诉给解密方；而在公钥密码体制中，这是不需要的。解密方只需要保证自己的私钥的保密性即可，对于公钥，无论是对加密方而言还是对密码分析者而言都是公开的，故无需考虑采用可靠的通道进行密码分发。这使得密钥管理和密钥分发的难度大大降低了。

4)         分清概念：加密和认证

加密是将数据资料加密，使得非法用户即使取得加密过的资料，也无法获取正确的资料内容。其重点在于数据的安全性。

身份认证是用来判断某个身份的真实性，确认身份后，系统才可以依不同的身份给予不同的权限。其重点在于用户的真实性。

两者的侧重点是不同的。

5)         摘要算法

摘要算法，又叫作Hash算法或散列算法，是一种将任意长度的输入浓缩成固定长度的字符串的算法(不同算法散列值长度不一样)，注意是“浓缩”而不是“压缩”，因为这个过程是不可逆的。它的特点是：

a)         不同内容的文件生成的散列值一定不同；相同内容的文件生成的散列值一定相同。由于这个特性，摘要算法又被形象地称为文件的“数字指纹”。

b)         不管文件多小（例如只有一个字节）或多大（例如几百GB），生成的散列值的长度都相同。



二、数字签名与数字信封

公钥密码体制在实际应用中包含数字签名和数字信封两种方式

1)         数字签名

指用户用自己的【私钥】对原始数据的哈希摘要进行加密所得的数据。数字签名定义两种互补的运算：一个用于签名，另一个用于验证。"私钥签名,公钥验证"

签名：发送方用特殊的hash算法，由明文中产生固定长度的【摘要】，然后利用自己的私钥对形成的摘要进行加密，这里加密后的数据就是数字签名。

验证：接受方利用发送方的公钥解密被加密的摘要得到结果A，然后对明文也进行hash操作产生摘要B.最后,把A和B作比较。此方式既可以保证发送方的身份正确性，又可以保证数据在传输过程中不会被篡改。

数字签名（Digital Signature）技术是不对称加密算法的典型应用。保证信息传输的完整性、发送者的身份认证、防止交易中的抵赖发生。

2)         数字信封

数字信封的功能类似于普通信封。普通信封在法律的约束下保证只有收信人才能阅读信的内容；数字信封则采用密码技术保证了只有规定的接收人才能阅读信息的内容。

数字信封中采用了单钥加密体制和公钥密码体制。信息发送者首先利用随机产生的【对称密码】加密信息(因为非对称加密技术的速度比较慢)，再利用接收方的【公钥】加密对称密码，被公钥加密后的对称密钥被称之为数字信封。在传递信息时，信息接收方要解密信息时，必须先用自己的私钥解密数字信封，得到对称密码，才能利用对称密码解密所得到的信息。

数字信封既发挥了对称加密算法速度快、安全性好的优点，又发挥了非对称加密算法密钥管理方便的优点。

三、应用示例

为了保证信息传送的真实性、完整性和不可否认性，需要对要传送的信息进行数字加密和数字签名。其传送过程如下：
发送者A：

1)         A准备要传送的数字信息(明文)

2)         A对数字信息(明文)进行哈希(hash)运算，得到一信息摘要。

3)         A用自己的【私钥(SK)】对信息摘要进行加密得到A的数字签名，并将其附在数字信息上。（数字签名）

4)         A随机产生一个加密钥(DES密钥)，并用此密钥对要发送的信息(明文)进行加密，形成密文。（对称加密）

5)         A用B的【公钥(PK)】对刚才随机产生的加密密钥进行加密，将加密后的DES密钥连同密文一起传送给B。（数字信封）

接收者B：

1)         B收到A传送过来的密文和加过密的DES密钥，先用自己的私钥(SK)对加密的DES密钥进行解密，得到DES密钥。

2)         B然后用DES密钥对受到的密文进行解密，得到明文的数字信息，然后将DES密钥抛弃(即DES密钥作废)。

3)         B用A的公钥(PK)对A的数字签名进行解密，得到信息摘要。

4)         B用相同的has算法对收到的明文再进行一次hash运算，得到一个新的信息摘要。

5)         B将收到的信息摘要和新生成的信息摘要进行比较，如果一致，说明收到的信息没有被修改过。