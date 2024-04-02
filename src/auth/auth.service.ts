import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';

import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { UsersService } from 'src/users/users.service';
import { AuthDto } from './dto/auth.dto';

type Tokens = {
  accessToken: string;
  refreshToken: string;
};

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signUp(createUserDto: CreateUserDto): Promise<Tokens> {
    const userExists = await this.usersService.findByUsername(
      createUserDto.username,
    );

    if (userExists) {
      throw new BadRequestException('User already exists');
    }

    const passwordHashed = await this.hashData(createUserDto.password);

    const newUser = await this.usersService.create({
      ...createUserDto,
      password: passwordHashed,
    });

    const tokens = await this.getTokens(newUser._id, newUser.username);

    await this.updateRefreshToken(newUser._id, tokens.refreshToken);

    return tokens;
  }

  async signIn(authDto: AuthDto): Promise<Tokens> {
    const userExists = await this.usersService.findByUsername(authDto.username);

    if (!userExists) {
      throw new BadRequestException('User does not exist');
    }

    const passwordMatch = await argon2.verify(
      userExists.password,
      authDto.password,
    );

    if (!passwordMatch) {
      throw new BadRequestException('Invalid credentials');
    }

    const tokens = await this.getTokens(userExists._id, userExists.username);

    await this.updateRefreshToken(userExists._id, tokens.refreshToken);

    return tokens;
  }

  async logout(userId: string) {
    await this.usersService.update(userId, { refreshToken: null });
  }

  private hashData(data: string) {
    return argon2.hash(data);
  }

  private async updateRefreshToken(userId: string, refreshToken: string) {
    const hashedRefreshToken = await this.hashData(refreshToken);

    await this.usersService.update(userId, {
      refreshToken: hashedRefreshToken,
    });
  }

  private async getTokens(userId: string, username: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(
        { sub: userId, username },
        {
          secret: this.configService.get('JWT_ACCESS_SECRET'),
          expiresIn: '15min',
        },
      ),
      this.jwtService.signAsync(
        { sub: userId, username },
        {
          secret: this.configService.get('JWT_REFRESH_SECRET'),
          expiresIn: '7d',
        },
      ),
    ]);

    return { accessToken, refreshToken };
  }
}
