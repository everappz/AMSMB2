Pod::Spec.new do |s|
  s.name             = 'AMSMB2'
  s.version          = '4.0.3'
  s.summary          = 'Swift library for SMB2/3 file operations using libsmb2'
  s.description      = <<-DESC
    This is a Swift library for SMB2/3 file operations for Apple platforms.
    It wraps libsmb2 to provide a high-level, thread-safe API for listing,
    reading, writing, copying, moving, and deleting files on SMB shares.
  DESC

  s.homepage         = 'https://github.com/everappz/AMSMB2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = 'Amir Abbas Mousavian'
  s.source           = { :git => 'https://github.com/everappz/AMSMB2.git', :tag => s.version.to_s }

  s.ios.deployment_target     = '13.0'
  s.osx.deployment_target     = '10.15'
  s.tvos.deployment_target    = '14.0'
  s.watchos.deployment_target = '6.0'
  s.visionos.deployment_target = '1.0'

  s.dependency 'libsmb2'

  s.pod_target_xcconfig = {
    'GCC_PREPROCESSOR_DEFINITIONS' => '$(inherited) HAVE_STDINT_H=1 HAVE_TIME_H=1',
  }

  s.swift_version = '6.0'
  s.default_subspecs = 'Swift'

  s.subspec 'Swift' do |ss|
    ss.source_files = 'AMSMB2/**/*.swift'
  end

  s.subspec 'ObjC' do |ss|
    ss.source_files = 'AMSMB2ObjC/**/*.{h,m}'
    ss.public_header_files = 'AMSMB2ObjC/AMSMB2Manager.h'
    ss.private_header_files = 'AMSMB2ObjC/SMB2Client.h', 'AMSMB2ObjC/SMB2FileHandle.h', 'AMSMB2ObjC/SMB2Directory.h', 'AMSMB2ObjC/SMB2Helpers.h'
  end
end
