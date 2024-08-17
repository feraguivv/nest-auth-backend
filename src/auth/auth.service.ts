import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register.dto';
import * as request from 'supertest';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bcrypt.hashSync(password, 10),
        ...userData,
      });
      await newUser.save(); // Solo guarda el documento, no retorna. // si se guarda correctamente, pasa a la siguiente linea, si no, cae en el catch
      const { password: _, ...user } = newUser.toJSON(); // Convierte a JSON y elimina password
      return user; // Retorna el JSON limpio sin password
    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists`);
      }
      throw new InternalServerErrorException('Something bad just happen');
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    const user = await this.create(registerUserDto);

    return {
      user: user,
      token: this.getJwtToken({ id: user._id }),
    };
  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email: email }); // buscará un usuaroi el cual su atributo email sea igual al email que le está pasando el loginDTO, el que se le pasa por el frontend
    if (!user) {
      throw new UnauthorizedException('Not valid credentials - invalid email');
    }
    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException(
        'Not valid credentials - invalid password',
      );
    }

    const { password: _, ...rest } = user.toJSON();

    return { user: rest, token: this.getJwtToken({ id: user.id }) };
  }

  async findAll(): Promise<User[]> {
    try {
      const users = await this.userModel.find();

      const usersWithoutPassword = users.map((user) => {
        const { password: _, ...rest } = user.toJSON();
        return rest;
      });

      return usersWithoutPassword;
    } catch (error) {
      throw new InternalServerErrorException(
        'No se pudo recuperar los usuarios',
      );
    }
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);

    const { password, ...rest } = user.toJSON();
    return rest;
  }

  generateNewLoginResponse(request: Request): LoginResponse {
    const user = request['user'] as User;
    return {
      user,
      token: this.getJwtToken({ id: user._id }),
    };
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }

  // findOne(id: number) {
  //   return `This action returns a #${id} auth`;
  // }

  // update(id: number, updateAuthDto: UpdateAuthDto) {
  //   return `This action updates a #${id} auth`;
  // }

  // remove(id: number) {
  //   return `This action removes a #${id} auth`;
  // }
}
