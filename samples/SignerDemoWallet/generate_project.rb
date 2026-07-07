#!/usr/bin/env ruby
# Generates SignerDemoWallet.xcodeproj.
#
# The demo compiles the integrator-side Signer Protocol sources directly from
# Shared/SignerProtocol (CSPIntegratorSession is the reference client), so the
# sample always tracks the in-repo protocol implementation.
#
# Run from this directory: ruby generate_project.rb

require 'xcodeproj'

PROJECT_PATH = File.expand_path('SignerDemoWallet.xcodeproj', __dir__)
REPO_ROOT = File.expand_path('../..', __dir__)

SHARED_SOURCES = %w[
  Shared/SignerProtocol/CSPCanonicalJSON.swift
  Shared/SignerProtocol/CSPCrypto.swift
  Shared/SignerProtocol/CSPEnvelope.swift
  Shared/SignerProtocol/CSPModels.swift
  Shared/SignerProtocol/CSPIntegratorSession.swift
  Shared/Crypto/CBOREncoder.swift
].freeze

APP_SOURCES = %w[
  SignerDemoWallet/SignerDemoApp.swift
  SignerDemoWallet/DemoWalletModel.swift
  SignerDemoWallet/DemoWalletView.swift
].freeze

project = Xcodeproj::Project.new(PROJECT_PATH)
target = project.new_target(:application, 'SignerDemoWallet', :ios, '17.0')

app_group = project.main_group.new_group('SignerDemoWallet', 'SignerDemoWallet')
APP_SOURCES.each do |path|
  file = app_group.new_file(File.expand_path(path, __dir__))
  target.add_file_references([file])
end

shared_group = project.main_group.new_group('SharedProtocol')
SHARED_SOURCES.each do |path|
  file = shared_group.new_file(File.join(REPO_ROOT, path))
  target.add_file_references([file])
end

target.build_configurations.each do |config|
  config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = 'watch.perpetua.signerdemo'
  config.build_settings['INFOPLIST_FILE'] = 'SignerDemoWallet/Info.plist'
  config.build_settings['CODE_SIGN_ENTITLEMENTS'] = 'SignerDemoWallet/SignerDemoWallet.entitlements'
  config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '17.0'
  config.build_settings['SWIFT_VERSION'] = '5.0'
  config.build_settings['TARGETED_DEVICE_FAMILY'] = '1'
  config.build_settings['DEVELOPMENT_TEAM'] = 'D282R2L62J'
  config.build_settings['CODE_SIGN_STYLE'] = 'Automatic'
  config.build_settings['GENERATE_INFOPLIST_FILE'] = 'NO'
  config.build_settings['CURRENT_PROJECT_VERSION'] = '1'
  config.build_settings['MARKETING_VERSION'] = '1.0'
end

project.save
puts "Generated #{PROJECT_PATH}"
