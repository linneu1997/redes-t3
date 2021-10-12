from iputils import *
import struct

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.identification = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        endereco, = struct.unpack('!I', str2addr(dest_addr))
        for tuplas in self.tabela:
            cidr = tuplas[0]
            excluir = 32 - int(cidr.split('/')[1])
            cidr, = struct.unpack('!I', str2addr(cidr.split('/')[0]))
            if (cidr >> excluir << excluir) == (endereco >> excluir << excluir):
                next_hop = tuplas[1]
                return next_hop

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        
        #cria o datagrama sem o valor de "Header Checksum"
        length = 20 + len(segmento)
        datagrama = struct.pack('!BBHHHBBH', 69, 0, length, self.identification, 0, 64, 6, 0)
        datagrama = datagrama + str2addr(self.meu_endereco) + str2addr(dest_addr)
      
        #calcula o checksum do cabeçalho e adiciona-o ao datagrama:
        checksum = calc_checksum(datagrama)
        datagrama = struct.pack('!BBHHHBBH', 69, 0, length, self.identification, 0, 64, 6, checksum)
        datagrama = datagrama + str2addr(self.meu_endereco) + str2addr(dest_addr)
        
        #concatena o segmento ao datagrama:
        datagrama = datagrama + segmento
        self.enlace.enviar(datagrama, next_hop)
        self.identification = self.identification + 1

